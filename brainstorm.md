# Secure communications over BitTorrent, powered by SodiumXT + TorrentXT

Status: **brainstorm / design exploration.** This is an ideas document, not a spec and not a
security guarantee. It sketches communication channels that piggyback on the BitTorrent network
(via TorrentXT) and are secured with modern cryptography (via SodiumXT). Several ideas here,
especially the metadata-privacy and multi-hop ones, are open problems flagged as such. Nothing
below has been implemented, threat-modeled to completion, or audited. Treat it as a menu to argue
with, then turn the chosen corner into a real protocol doc.

House style: no em-dashes (hyphens, commas, colons, parentheses instead).

---

## 0. The thesis

You have already built the two halves of a serverless, censorship-resistant messaging stack
without noticing they were halves:

- **TorrentXT** gives you a planet-scale, decentralized **rendezvous-and-transport fabric**: the
  Kademlia DHT (find anyone, store small signed values), the peer wire protocol (talk directly to
  anyone you found), trackers, and swarms (crowds to hide in).
- **SodiumXT** gives you the **confidentiality, authentication, key agreement, and identity** to
  make anything you push through that fabric private and unforgeable.

The keystone: the **ed25519 identity is shared** between them. A BEP44 signature and
`sxSignDetached` are the same primitive over the same key, so a single keypair is simultaneously
your BitTorrent identity, your DHT-record signing key, and your cryptographic name. One seed, two
networks.

What this combination buys, that neither library buys alone: **communication with no server to
run, seize, subpoena, or block**, where the content is authenticated encryption and the transport
is indistinguishable (at its best) from ordinary file sharing.

What it does NOT buy for free, stated up front so the rest of the document stays honest: **IP-level
anonymity** (peers and the DHT see your address), **metadata privacy** (the DHT is public and
crawlable), and **abuse resistance** (open, serverless inboxes invite spam). Sections 8 and 11 deal
with these squarely.

---

## 1. The substrate: BitTorrent primitives mapped to SodiumXT crypto

| BitTorrent primitive (TorrentXT) | Repurposed as | Secured with (SodiumXT) |
|---|---|---|
| DHT `announce_peer` / `get_peers` on a 20-byte infohash (BEP5) | A **rendezvous point**. Anyone announcing the same id discovers each other's IP:port. The id need not map to real content. | `sxKdfDerive` / `sxHash(secret, 20)` to derive a rotating, unguessable 160-bit id |
| DHT mutable item, signed + seq-numbered + ~1000 bytes (BEP44) | A **decentralized signed mailbox / feed slot** keyed by your public key | `sxSignDetached` is the BEP44 signature; `sxSeal` / `sxBox` for the payload |
| DHT immutable item, keyed by hash of value (BEP44) | A **content-addressed encrypted blob** (a decentralized pastebin cell) | `sxSeal` + `sxHash` addressing |
| Peer wire extension messages (BEP10) | An **arbitrary bidirectional channel** between two connected peers | `sxSecretStream*` session (per-chunk auth + ordering + a FINAL tag) |
| A real torrent and its swarm (BEP3/BEP52) | **Cover traffic** and a **bulk payload carrier** | `sxEncryptFile` / `sxDecryptFile` for the payload |
| Peer exchange gossip (BEP11) | A **flood/gossip bus** for group messages | `sxAeadEncrypt` framing, `sxSecretBox` room key |
| Metadata exchange (BEP9), `peer_id`, ports, timing | **Low-bandwidth covert carriers** | AEAD micro-frames, `sxHash` derived symbols |

A note on identifiers: the mainline DHT keyspace is 160-bit, so derived rendezvous ids should be
**20 bytes** (`sxHash(data, 20)`; BLAKE2b accepts 16..64). Real infohashes are SHA-1 (v1) or
SHA-256 (v2) of the info dictionary, but the DHT does not verify that an announced id corresponds
to real content, which is exactly why a *derived* id works as a private meeting place.

---

## 2. Design axes (so every idea has coordinates)

Every channel below can be positioned on these axes. Picking coordinates first is how you avoid
building the wrong thing.

- **Timing:** asynchronous (store-and-forward, recipient offline) vs. synchronous (both online).
- **Fan-out:** 1:1, 1:many (broadcast), or many:many (group).
- **Who is hidden:** content only, sender identity, recipient identity, or the mere fact that a
  channel exists (existence hiding / deniability).
- **Deniability tier:**
  1. *Encrypted-but-visible*: "something private is happening at this DHT key."
  2. *Unattributed swarm*: "this looks like a swarm for some unknown torrent."
  3. *Cover-seeded*: "this provably looks like two people sharing Ubuntu."
- **Adversary:** passive network observer, platform/ISP censor, DHT-Sybil actor, global passive
  adversary with IP correlation. The design cost rises steeply left to right.

---

## 3. Foundations (every channel stands on these)

### 3.1 Identity and keys

One master seed (32 bytes, `sxRandomBytes(32)`, stored the way you store any root secret). From it:

- **Signing / naming key:** `sxSignKeypairFromSeed(seed, ...)` gives the ed25519 keypair that is
  your BitTorrent/BEP44 identity and your cryptographic name.
- **Encryption key:** an X25519 keypair for `sxBox` / `sxSeal`, and/or a `sxKeyExchangeKeypair`
  (crypto_kx) keypair for session agreement.

Capability gap worth closing in SodiumXT: to make ALL of these deterministic from one master seed
(so the whole identity is one backup), expose a **seeded** box/kx keypair (`crypto_box_seed_keypair`
/ `crypto_kx_seed_keypair`) and/or the **ed25519 -> X25519 conversion**
(`crypto_sign_ed25519_pk_to_curve25519`). Until then, derive per-purpose seeds with
`sxKdfDerive(masterKey, id, "sxidenty")` and store the resulting keypairs. This is a small, safe
addition and it makes "one keypair, two networks" literally true.

### 3.2 Discovery / rendezvous

The universal move: turn a shared secret and a time epoch into a meeting id.

```
rendezvousId = sxHash(sharedSecret & epochBytes, 20)      -- 160-bit DHT key
both sides: DHT announce_peer(rendezvousId) + get_peers(rendezvousId)
-> each learns the other's IP:port, then connects over the peer wire
```

Rotate `epoch` (per hour/day) so the meeting point moves and long-term correlation is bounded. For
a first contact with someone whose secret you do not yet share, the meeting id is derived from
their **public** key instead (Section 3.3).

### 3.3 Addressing and mailboxes

- **Direct inbox:** `inboxKey = sxHash(recipientPub & counter, 20)`. Senders write there; recipient
  scans counters. Simple, but the recipient's key is guessable to anyone who knows their pubkey, so
  pair with anti-spam (Section 7) and k-anonymity (Section 7) when recipient privacy matters.
- **Prekey bundle:** the recipient publishes, as a BEP44 mutable item under their identity key, a
  signed bundle of one-time X25519 prekeys (an X3DH-style setup). Senders fetch it, agree a key,
  and get forward secrecy from message one.

### 3.4 Verification and key transparency

- **Safety numbers:** `sxHash(aPub & bPub, 32)` rendered as words or a QR, compared out of band,
  checked with `sxMemEqual`. Defends against a man-in-the-middle at first contact.
- **Key-transparency log:** publish key changes as an append-only, seq-chained BEP44 feed (each
  entry signs the previous entry's hash). Contacts follow it and detect a malicious DHT node that
  tries to substitute your prekey bundle. This is the main defense against the DHT lying about your
  keys, and it is cheap to add.

---

## 4. The channels

Each is written as a mini-spec: what it is, its coordinates, the substrate, the flow, the crypto,
the properties, the limits, and why it is novel. IDs (C1..) are for cross-reference.

### C1. DHT Mailbox (async 1:1) - "Signal without servers"

- **What:** offline-capable private messaging using the DHT as both the key directory and the
  message queue.
- **Coordinates:** async, 1:1, content + (optionally) sender hidden, tier 1-2.
- **Substrate:** BEP44 mutable (prekeys) + BEP44 immutable/mutable (message cells).
- **Flow:**
  ```
  setup:  recipient publishes signed prekey bundle at BEP44(identityPub)
  send:   sender fetches bundle -> X3DH-style agree (sxKeyExchangeClient / sxBox)
          msg = sxSeal(pad(plaintext), recipientPrekeyPub)          -- anonymous sender
          put msg at inboxKey = sxHash(recipientPub & counter, 20)
  recv:   recipient scans counters, sxSealOpen(...) trial-decrypts
  ratchet: next message key = sxKdfDerive(chainKey, counter, "sxratch1")
  ```
- **Crypto:** `sxKeyExchange*` or `sxBox` for the handshake, `sxSeal` for sealed-sender delivery,
  `sxKdfDerive` for the ratchet, `sxPad` to hide length.
- **Properties:** confidentiality, integrity, forward secrecy (ratchet), sender anonymity (sealed
  box). Recipient is addressable by pubkey (mitigate with C-anon inboxes).
- **Limits:** ~1000 bytes per cell (chunk, or store a pointer to an encrypted torrent for bulk);
  DHT churn requires periodic re-put; open inbox needs anti-spam.
- **Novelty:** BEP44's *signed mutable item* is a natural, decentralized prekey server, and the
  DHT keyspace is a natural message queue. No prior consumer product wires exactly these together
  over the mainline DHT with a modern ratchet.

### C2. Phantom Swarm (realtime 1:1) - a swarm with no torrent

- **What:** a live encrypted session between two people who meet in a swarm that has no content.
- **Coordinates:** sync, 1:1, existence-obscured (tier 2).
- **Substrate:** DHT rendezvous (BEP5) -> peer wire extension messages (BEP10).
- **Flow:**
  ```
  both derive rendezvousId (3.2), announce, get_peers, connect
  handshake: prove shared-secret knowledge without revealing it
     A -> B: nonce
     B -> A: sxAeadEncrypt(nonce, ad=epoch, sharedKey); A verifies, then symmetric
  session:  sxSecretStreamInitPush -> exchange header -> sxSecretStreamPush/Pull per message
  ```
- **Crypto:** `sxAeadEncrypt` challenge/response for mutual auth, `sxSecretStream*` for the live
  channel (ordering + per-chunk auth + truncation detection built in).
- **Properties:** confidentiality, integrity, mutual auth, forward-ish (rekey the stream), and the
  channel's *existence* is hidden inside a plausible swarm.
- **Limits:** both must be online; IP is exposed to the peer (see C11/C12 for the privacy layer);
  the swarm being contentless is a subtle tell to a very careful observer (see C3 to remove it).
- **Novelty:** the swarm membership *is* the channel; the "torrent" is a MacGuffin.

### C3. Cover-Seed Channel (deniable realtime) - hide inside a real swarm

- **What:** C2, but you both genuinely seed a popular innocuous torrent, and the conversation rides
  the existing peer connection as extension messages.
- **Coordinates:** sync, 1:1, tier 3 (strongest deniability).
- **Substrate:** a real torrent + BEP10 custom extension messages.
- **Flow:**
  ```
  both seed <popular ISO>. In the BEP10 extended handshake, advertise a benign-looking
  extension and place an ed25519-signed recognition token where a client-version string sits.
  On recognizing a token that verifies against a known contact key (sxSignVerifyDetached),
  open a sxSecretStream session inside custom extension messages on that same connection.
  ```
- **Crypto:** `sxSignDetached` / `sxSignVerifyDetached` for peer recognition, `sxSecretStream*` for
  the tunnel.
- **Properties:** to the tracker, the DHT, and a passive tap you are two clients sharing Ubuntu.
  Traffic-analysis resistance and plausible deniability are the headline.
- **Limits:** capacity competes with real seeding traffic (a feature for cover, a limit for
  throughput); recognition tokens must be unlinkable across sessions (rotate them, derive per-epoch).
- **Novelty:** deniability by *doing a real, legal thing* and tunneling inside it, rather than by
  obfuscation alone. This is the most interesting corner in the whole document.

### C4. Signed Encrypted Feed (1:many broadcast) - an un-censorable channel

- **What:** a decentralized, authenticated, encrypted "podcast/RSS/Telegram channel."
- **Coordinates:** async, 1:many, content hidden, publisher authenticated, tier 1.
- **Substrate:** BEP44 mutable (the signed index) -> encrypted torrents (the payloads).
- **Flow:**
  ```
  publish: body -> sxEncryptFile -> torrent T (infohash H, key K)
           entry = sxSign( {seq, H, K_wrapped, prevHash}, publisherSk )
           put entry at BEP44(publisherPub, salt="feed") with seq = n
  follow:  subscribers hold publisherPub (+ channel read key); fetch seq 0..n,
           verify sxSignOpen, unwrap K, download T, sxDecryptFile
  ```
- **Crypto:** `sxSign`/`sxSignOpen` for the signed, ordered index; `sxEncryptFile` for payloads;
  `sxKdfDerive` to rotate the channel read key (forward secrecy for the audience, and reader
  revocation by rekey).
- **Properties:** authenticity and ordering (seq + prev-hash chain), confidentiality to the reader
  set, no host to seize, natural fan-out via the swarm.
- **Limits:** membership/revocation for a large audience is the hard part (sender-key or tree-based
  rekey, Section 7); the *set* of subscribers is observable at the swarm level.
- **Novelty:** exactly the "feed signing" your SodiumXT plan anticipated, generalized into a full
  broadcast medium. The signed BEP44 index over encrypted torrents is a clean, buildable primitive.

### C5. Group Rooms (many:many)

- **What:** a shared encrypted room for N members.
- **Coordinates:** sync or async, N:N, tier 1-2.
- **Substrate:** rotating room infohash (rendezvous) + peer-wire or PEX-style gossip.
- **Flow:**
  ```
  room key R (shared out of band or via pairwise C1). Rendezvous at sxHash(R & epoch, 20).
  each member has a sender key SK_i = sxKdfDerive(R, memberId_i, "sxsender")
  message = sxAeadEncrypt(pad(text), ad=memberId & seq, SK_i); flood to connected members
  ```
- **Crypto:** `sxSecretBox` / `sxAeadEncrypt` with per-member sender keys, `sxKdfDerive` for member
  management, `sxSignDetached` if you also want cross-member non-repudiation.
- **Properties:** per-sender authentication, add/remove by re-deriving keys, no central room server.
- **Limits:** membership churn and forward secrecy for groups is genuinely hard (this is the MLS
  problem); start with static small rooms, graduate to a tree-based ratchet later.
- **Novelty:** using `sxKdfDerive` sender keys over a swarm-gossip transport gives a serverless
  group with a clean key-management story.

### C6. Content-Addressed Drop + Capability Links (async object sharing)

- **What:** a self-contained "unlock link" to an encrypted object anyone with the link can open.
- **Coordinates:** async, 1:many-by-possession, tier 1.
- **Substrate:** an encrypted torrent (or immutable BEP44 cell) + an out-of-band link.
- **Flow:**
  ```
  seal:   sxEncryptFile(file) -> torrent (infohash H, key K)
  link:   bt-secure://H#base64(K)     (K never touches the network)
  open:   fetch by H from the swarm, sxDecryptFile with K
  ```
- **Crypto:** `sxEncryptFile`/`sxDecryptFile`, `sxBin2Base64` for the fragment, optional `sxSeal`
  wrapping if the link should be openable only by one recipient.
- **Properties:** the key lives only in the link fragment (like a password-in-URL, but authenticated
  encryption), the swarm distributes ciphertext, revocation by re-encrypting under a new key.
- **Novelty:** a decentralized, authenticated "encrypted share link" whose payload is a self-hosting
  swarm rather than a company's bucket.

### C7. Private Presence Beacons - "online now," without a server

- **What:** let a contact know you are reachable, visible to nobody else.
- **Coordinates:** sync-signaling, 1:1, tier 2.
- **Substrate:** per-contact derived infohash you only announce while online.
- **Flow:**
  ```
  presenceId = sxHash(pairwiseSecret & "presence" & epoch, 20)
  online -> announce_peer(presenceId); contact's get_peers(presenceId) sees you -> escalate to C2/C3
  ```
- **Crypto:** `sxKdfDerive` for the per-contact, per-epoch id.
- **Properties:** presence is a capability (only the contact can derive the id), and it doubles as
  the rendezvous for an interactive session.
- **Limits:** announcing is an IP disclosure to the DHT; rotate and pair with the privacy layer.

### C8. Public Authenticated Wall (1:many, not secret but unforgeable)

- **What:** a decentralized, signed, censorship-resistant public feed (think a self-owned, un-de-
  platformable microblog).
- **Coordinates:** async, 1:many, public content, authenticated, tier 0 (not hidden, by design).
- **Substrate:** BEP44 mutable seq-chain (like C4 without encryption).
- **Crypto:** `sxSign`/`sxSignVerifyDetached`, a seq + prev-hash chain for tamper-evident ordering.
- **Novelty:** the "trust the key, not the host" publishing model, using the same identity that
  runs your private channels.

### C9. Time-Locked and Dead-Man Messages

- **What:** messages that unlock later, or that publish automatically if you stop checking in.
- **Coordinates:** async, 1:1 or 1:many, tier 1.
- **Substrate:** publish ciphertext now, reveal the key on a schedule or via a threshold.
- **Flow (dead-man):**
  ```
  now:   put sxSeal(secret) as an immutable BEP44 cell; keep the key K offline
  heartbeat: periodically re-put a "still here" mutable item
  trigger:   if heartbeats stop, a pre-arranged set of holders publishes their shares of K
             (split K with a secret-sharing scheme; SodiumXT gives the AEAD, the sharing is a
             small add-on) -> the cell becomes openable
  ```
- **Crypto:** `sxSeal` for the payload; a k-of-n secret-sharing layer over the key (a capability to
  add alongside SodiumXT).
- **Novelty:** the DHT's built-in expiry and the swarm's redundancy make "publish on my silence" a
  natural fit.

### C10. Multi-Hop Relay ("garlic over BitTorrent") - the IP-privacy layer

- **What:** route sealed messages through willing swarm peers so the write to a recipient's inbox
  does not come from your address.
- **Coordinates:** async, adds recipient/sender IP unlinkability, tier 2-3. **Speculative and hard.**
- **Substrate:** onion-wrap a message in nested sealed boxes, each layer addressed to a relay's
  key; relays peel one layer and forward to the next DHT inbox.
- **Flow:**
  ```
  onion = sxSeal( relay1Instr & sxSeal( relay2Instr & sxSeal(finalMsg, dstPub), r2Pub), r1Pub)
  each relay: sxSealOpen -> learns only "next hop" + inner blob -> writes it forward
  ```
- **Crypto:** nested `sxSeal`/`sxSealOpen` (each hop learns only its successor), padding to a fixed
  size so layers are indistinguishable.
- **Open problems:** relay incentives, Sybil relays, timing correlation, reliability. This is
  essentially building a mixnet on top of the swarm and should be treated as a research track, not
  a v1 feature. Included because it is the honest answer to "but my IP leaks."

### C11. Covert / Steganographic Micro-Channels (max deniability, min bandwidth)

- **What:** communicate where even "using the DHT to talk" must be invisible.
- **Coordinates:** async, tiny capacity, tier 3.
- **Substrate / carriers:** the *choice* of infohashes you announce (each id = a symbol), the
  *timing* of announces/requests (a timing code), or a few AEAD bytes tucked into `peer_id`/port
  entropy or BEP9 metadata padding.
- **Crypto:** `sxAeadEncrypt` micro-frames, `sxHash`-derived symbol alphabets, `sxMemEqual` checks.
- **Properties:** traffic is indistinguishable from ordinary DHT churn; capacity is bytes, not
  kilobytes; fragile against active manipulation.
- **Use:** a bootstrap channel to establish a shared secret, then graduate to C2/C3.

---

## 5. Cross-cutting mechanisms (steal these into any channel)

- **Ratchet keyed by the network:** use the BEP44 `seq` number as the KDF/ratchet index
  (`sxKdfDerive(chainKey, seq, ctx)`), so the DHT itself carries ratchet state and both sides stay
  in sync without extra messages.
- **Forward-secrecy-by-forgetting:** DHT items expire (TTL, churn). Ephemeral messages self-destruct
  because the network forgets, no explicit delete required, no tombstones to leak.
- **k-anonymous inboxes:** address a bucket *prefix* rather than one recipient. A set of recipients
  all fetch the bucket and trial-decrypt; sealed-box auth means only the intended one opens. Hides
  *who* you write to inside an anonymity set.
- **Anti-spam for open inboxes:** gate writes with a small proof-of-work bound to the inbox+epoch,
  or with a capability token (a MAC the recipient issued to known senders), checked before you
  spend effort trial-decrypting. Without this, serverless inboxes are a spam magnet.
- **Length hiding:** `sxPad` every payload to a bucketed size so ciphertext length stops leaking
  message length; `sxUnpad` on open.
- **Cover traffic:** join swarms and write decoy cells you never read, so real activity hides in a
  baseline of noise. Cheap, and it directly attacks traffic analysis.
- **Replay/reorder binding:** put `epoch` and `seq` in the AEAD associated data (`sxAeadEncrypt`
  ad=...), so a replayed or reordered ciphertext fails to open.
- **Rotation everywhere:** rotate rendezvous ids, prekeys, and recognition tokens per epoch so a
  crawler that catalogs the DHT cannot link two epochs of the same channel.

---

## 6. Security-properties matrix

Rough posture per channel. "part" = partial / needs a specific mechanism from Section 5; "NA" = not
applicable to that channel's shape.

| Channel | Confid. | Auth | Fwd secrecy | Sender anon | Recipient privacy | Deniability | Censorship-resist | Metadata privacy | Async | Realtime |
|---|---|---|---|---|---|---|---|---|---|---|
| C1 Mailbox | strong | strong | strong | strong | part | tier1 | strong | part | yes | no |
| C2 Phantom swarm | strong | strong | part | no | part | tier2 | strong | part | no | yes |
| C3 Cover-seed | strong | strong | part | no | part | tier3 | strong | strong | no | yes |
| C4 Enc. feed | strong | strong | part | NA (pub) | part | tier1 | strong | part | yes | no |
| C5 Rooms | strong | strong | part | no | part | tier1 | strong | part | both | both |
| C6 Cap links | strong | strong | none | strong | NA | tier1 | strong | part | yes | no |
| C7 Presence | NA | strong | NA | no | strong | tier2 | strong | part | no | yes |
| C8 Public wall | none | strong | NA | no | NA | tier0 | strong | none | yes | no |
| C9 Time-lock | strong | strong | NA | strong | part | tier1 | strong | part | yes | no |
| C10 Multi-hop | strong | strong | part | strong | strong | tier2 | strong | part | yes | no |
| C11 Covert | strong | strong | part | strong | strong | tier3 | strong | strong | yes | no |

The columns that are hardest to turn from "part" to "strong" are **metadata privacy** and
**recipient privacy**. That is where the real research is, and where C10/C11 and the Section 5
mechanisms earn their keep.

---

## 7. What TorrentXT needs to expose

Most of these channels are gated less by crypto (SodiumXT already covers it) than by which
BitTorrent capabilities the binding surfaces. The high-value additions:

1. **Raw DHT `announce_peer` / `get_peers` on an arbitrary 20-byte id** (rendezvous, presence).
2. **BEP44 `put` / `get`, both mutable (signed, seq, salt) and immutable** (mailboxes, feeds, cells).
   The signing hook should accept an externally produced ed25519 signature so SodiumXT signs it.
3. **BEP10 custom extension messages: register a message type, send and receive raw payloads on a
   peer connection** (C2, C3, C5). This is the single most enabling addition.
4. **Add/seed a torrent by infohash or magnet, with the encrypted-file helpers wired in** (C4, C6).
5. **Peer/connection events and access to the extended handshake fields** (C3 recognition tokens).
6. **A "phantom torrent" mode:** announce/participate in a swarm id without needing real content
   metadata (C2, C7).

And the small SodiumXT additions noted inline: **seeded box/kx keypairs** and/or **ed25519 ->
X25519 conversion** (one-seed identity, Section 3.1), and optionally a **k-of-n secret-sharing**
helper (C9).

---

## 8. The hard parts (so "secure" stays honest)

- **The DHT is public and crawlable.** Content confidentiality is easy; hiding which ids are hot,
  who announces, and when is the actual problem. Rotating derived ids, k-anonymity, padding, and
  cover traffic are mandatory, not garnish.
- **No IP anonymity by default.** Peers and DHT nodes see your address. This stack delivers
  decentralization + confidentiality + deniability, not sender-IP anonymity. For that, run it over
  Tor/I2P, or build C10, and say so plainly to users.
- **Sybil and eclipse attacks.** An adversary can place nodes near a target DHT key to censor or
  surveil a specific mailbox/rendezvous. Mitigate with key rotation, redundant ids, republication,
  and never trusting a single lookup.
- **Size and reliability.** BEP44 is ~1000 bytes and items must be periodically re-put. Treat the
  DHT as a signaling/pointer layer; put bulk in encrypted torrents.
- **Spam and DoS on open inboxes.** Serverless writability cuts both ways; see Section 5 anti-spam.
- **Group forward secrecy** (C5) and **large-audience revocation** (C4) are genuinely hard (MLS-
  class problems). Start static and small.
- **Key loss and recovery.** No server means no password reset. Backup and social-recovery UX is a
  first-class design problem, not an afterthought.

---

## 9. Responsible design and abuse resistance

A serverless, deniable, censorship-resistant channel is a powerful privacy tool and, like all such
tools, needs abuse-resistance baked in rather than bolted on:

- **Open inboxes need rate-limiting / proof-of-work** or they become spam and malware drops.
- **Broadcast and group channels are trust-on-key:** the value is that you can verify *who* signed,
  so the UX must make key verification (safety numbers, key transparency) easy and prominent.
- **Piggybacking on public swarms has legal and ToS dimensions** that vary by jurisdiction and by
  the torrents you attach to; cover-seeding (C3) should use content that is lawful to share.
- **Content moderation is the user's, not a server's**, so give recipients strong blocking,
  allow-listing, and report/verify primitives. Design for consent (senders you accepted), not open
  reachability, by default.

Building these in from day one is both the ethical default and, practically, what keeps the system
usable instead of drowning in spam.

---

## 10. Where to start (a phased path)

1. **Identity + discovery + verification** (Section 3): one-seed identity, derived rendezvous,
   safety numbers, a key-transparency feed. Everything else needs these.
2. **C1 Mailbox** (async core) and **C2 Phantom Swarm** (realtime core) on that identity. This is a
   working serverless messenger and proves the two-network keystone end to end.
3. **C3 Cover-Seed** for deniability and **C4 Encrypted Feed** for broadcast. These are the two
   "wow" demos and they exercise the peer-wire and swarm-payload paths respectively.
4. **Section 5 mechanisms** hardening: padding, cover traffic, anti-spam, ratchet-by-seq.
5. **Research tracks:** C10 multi-hop (IP privacy) and strong metadata privacy. Treat as R&D.

The first buildable milestone is small: identity (Section 3.1) + rendezvous (3.2) + a `sxSecretStream`
tunnel over one BEP10 extension message (C2). That single vertical slice validates the whole idea.

---

## 11. Open research questions

- How much metadata privacy can rotating derived ids + k-anonymity + cover traffic actually buy
  against a DHT-crawling adversary, quantitatively?
- Can C3 cover-seeding survive an adversary who runs the tracker and does fine-grained traffic
  analysis of the peer connection?
- What is the cheapest anti-spam (PoW vs. capability tokens) that keeps open inboxes usable?
- Group key management (C5) without a server: how far can `sxKdfDerive` sender-keys go before you
  genuinely need an MLS-style tree?
- Is a swarm-native mixnet (C10) viable, or does it inevitably reduce to "just use Tor underneath"?
- Reliability: how aggressively must BEP44 items be re-published, and can subscribers share the
  republication load without revealing themselves?

---

## 12. Naming, if it helps the vision feel real

Working names to argue over: the stack as **"Currents"** or **"Riptide"** (it moves through the
torrent), the deniable cover-seed mode as **"Undertow,"** the async mailbox as **"Driftwood,"** the
signed feed as **"Beacon."** Names are free; pick later.

---

### One-paragraph pitch

*One ed25519 keypair is your name on two networks. Your friends find you at a meeting point only
your shared secret can compute, in a swarm that looks like any other. Your words are sealed with
authenticated encryption before they ever touch the wire, and the wire is the same BitTorrent
traffic the whole world already runs. There is no server to seize, no directory to subpoena, no
switch to flip. That is what SodiumXT and TorrentXT are, once you notice they were two halves of the
same thing.*
