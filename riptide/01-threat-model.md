# 01. Threat model

A protocol is only as meaningful as the adversary it names. This document states who Riptide
defends against, what it promises, and, just as important, what it does not.

## Assets

- **Message content** (the plaintext of a conversation, feed, or object).
- **Identity keys** (the master seed and the keys derived from it).
- **Relationship metadata** (who talks to whom, when, how often, group membership).
- **Existence of a channel** (that any private communication is happening at all).
- **Network location** (the IP address behind an identity).

## Adversaries

Riptide is designed against a ladder of adversaries. Higher rungs are strictly harder and cost more
to defend; a deployment should state which rung it targets.

1. **Passive network observer** (an ISP, a coffee-shop sniffer, an on-path tap). Sees your traffic
   but does not participate in the DHT or the swarm.
2. **Platform / service censor.** Wants to block the *ability* to communicate: drop specific
   traffic, seize a server, compel a provider. Riptide's decentralization is aimed squarely here.
3. **Active DHT participant / Sybil.** Runs many DHT nodes, can target a specific key (eclipse it,
   censor puts/gets, log who queries it), and crawls the DHT to catalog activity.
4. **Swarm insider.** Joins swarms you use, sees peer lists and your IP, can attempt active
   manipulation of peer-wire traffic.
5. **Global passive adversary with correlation.** Observes large fractions of the network and
   correlates timing and volume across links. This is the hardest rung; Riptide does not claim to
   defeat it, and only the cover-seed and multi-hop extensions even approach it.

## Security goals (what Riptide aims to guarantee)

For the adversary rungs noted:

- **G1 Confidentiality (rungs 1-4):** message content is readable only by intended recipients.
  Provided by authenticated encryption (sealed boxes, boxes, AEAD, secretstream). Every ciphertext
  carries a Poly1305 tag; there is no unauthenticated mode.
- **G2 Integrity and authenticity (rungs 1-4):** tampering, forgery, and wrong keys are detected
  and rejected, never silently accepted. Feeds and records are ed25519-signed; sessions are AEAD.
- **G3 Forward secrecy (rungs 1-4, where the channel supports it):** compromise of a long-term key
  does not retroactively decrypt past messages that used ratcheted or ephemeral keys (mailbox,
  session). Feeds and static objects provide this only via key rotation, not per-message.
- **G4 Replay and reorder resistance (rungs 1-4):** a captured ciphertext cannot be replayed or
  reordered undetected, because the epoch and sequence are bound into each envelope as associated
  data, and BEP44 sequence numbers are monotonic.
- **G5 Censorship resistance (rung 2, and rung 3 with effort):** there is no chokepoint to seize.
  Against a Sybil that eclipses one DHT key, redundancy and rotation raise the cost (G5 is weaker at
  rung 3; see limits).
- **G6 Deniability (cover-seed mode, rungs 1, 2, 4):** the *existence* of a conversation is hidden
  inside a real, lawful BitTorrent transfer, so an observer sees ordinary file sharing.
- **G7 Sender anonymity (mailbox, objects):** a sealed-box message does not reveal who sent it,
  even to the recipient, unless the sender chooses to sign.

## Non-goals and honest limits

These are not bugs; they are the boundary. State them to users.

- **N1 No IP anonymity by default.** Peers and DHT nodes learn your IP. Rungs 3-4 can map an
  identity or a rendezvous id to an address. Mitigations: run Riptide over Tor/I2P, or use the
  multi-hop relay extension ([10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md)), which is
  itself an open research track, not a finished guarantee.
- **N2 Incomplete metadata privacy.** The DHT is public. Rotation, k-anonymous inboxes, padding, and
  cover traffic raise the cost of linking and enumeration, but a determined rung-3 crawler can still
  learn a great deal about which ids are active and when. Riptide reduces metadata leakage; it does
  not eliminate it.
- **N3 No defense against a global passive adversary (rung 5)** beyond what cover-seed and multi-hop
  approximate. Traffic-confirmation attacks by an omniscient observer are out of scope.
- **N4 No content moderation.** Riptide authenticates *who* said something so recipients can decide
  whom to trust; it does not and cannot filter content centrally. Recipient-side blocking,
  allow-listing, and verification are the model ([10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md)).
- **N5 No recovery of a lost master seed.** No server means no reset. Backup and social recovery are
  a design responsibility ([02-identity.md](02-identity.md)), not a safety net Riptide provides.
- **N6 Endpoint security is assumed.** If the device is compromised, keys and plaintext are exposed.
  SodiumXT is honest that secrets in script-managed memory cannot be locked or wiped; Riptide
  inherits that boundary.
- **N7 Availability is best-effort.** DHT churn, eclipse attacks, and swarm death can delay or block
  delivery. Riptide favors confidentiality and integrity over guaranteed delivery.

## Trust assumptions

- **The user's endpoint is trusted.** (N6.)
- **The master seed is secret and backed up.** (N5.)
- **First-contact key authenticity is verified out of band** (safety numbers / QR) or via the
  key-transparency log ([02-identity.md](02-identity.md)). Without one of these, a rung-3 adversary
  that controls the DHT lookup can attempt a man-in-the-middle on first contact.
- **libsodium and the SodiumXT/TorrentXT bindings are correct.** Riptide adds no cryptography of its
  own; it composes audited primitives.

## Attack surface and mitigations (summary)

| Attack | Rung | Mitigation | Residual risk |
|---|---|---|---|
| Read message content | 1-4 | Authenticated encryption (G1) | Endpoint compromise (N6) |
| Forge/tamper messages | 1-4 | AEAD + ed25519 signatures (G2) | none if keys secret |
| Replay/reorder | 1-4 | epoch+seq in AD, BEP44 monotonic seq (G4) | none within a channel |
| MITM at first contact | 3 | safety numbers / key-transparency log | user skips verification |
| Eclipse a DHT key | 3 | rotation, redundant ids, republication (G5) | targeted censorship persists |
| Link two epochs of a channel | 3 | rotate ids/keys per epoch (principle 4) | intra-epoch linkage |
| Enumerate active channels | 3 | derived unguessable ids, cover traffic (N2) | statistical exposure |
| De-anonymize IP | 3-4 | Tor/I2P underlay, multi-hop (N1) | default deployment leaks IP |
| Spam an open inbox | any | PoW / capability tokens (doc 10) | cost, not elimination |
| Confirm a conversation | 5 | cover-seed, multi-hop (partial) | not defeated (N3) |
| Lose the master seed | n/a | backup, social recovery (N5) | user error is fatal |

## How to read the rest of the spec against this model

Every channel document ends with a short "security properties" note stating which goals (G1-G7) it
achieves and against which rungs, and which non-goals (N1-N7) apply. When a design choice trades one
property for another (throughput vs. deniability, availability vs. metadata hiding), the document
names the trade rather than hiding it.
