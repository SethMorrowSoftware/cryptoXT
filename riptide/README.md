# Riptide

**A protocol for secure, serverless communication that rides the BitTorrent network.**

Riptide is a set of communication protocols built from two OpenXTalk extensions:

- **TorrentXT** provides the transport and rendezvous fabric: the Kademlia DHT (BEP5), signed
  mutable/immutable DHT records (BEP44), the peer wire extension protocol (BEP10), and swarms.
- **SodiumXT** provides the cryptography: ed25519 identity and signatures, X25519 boxes and sealed
  boxes, crypto_kx key agreement, XChaCha20-Poly1305 AEAD and secretstream, Argon2id, BLAKE2b, the
  BLAKE2b KDF, and a real CSPRNG.

The keystone is that a single ed25519 keypair is simultaneously your BitTorrent identity, your
BEP44 record-signing key, and your cryptographic name. One seed, two networks.

Riptide gives you communication with **no server to run, seize, subpoena, or block**, where the
content is authenticated encryption and, at its strongest, the transport is indistinguishable from
ordinary file sharing.

## Status

**Specification draft, version 0.1 (pre-implementation).** This directory expands
[`../brainstorm.md`](../brainstorm.md) into a full protocol spec. It is a design under active
development: concrete enough to implement and to threat-model against, but not yet built, not yet
independently reviewed, and not yet a security guarantee. Where a design is speculative or an open
research problem, it says so.

House style: ASCII only, no em-dashes (hyphens, commas, colons, parentheses instead).

## What Riptide deliberately does and does not provide

**Does:** confidentiality and integrity (authenticated encryption everywhere), sender and message
authentication, forward secrecy where the channel supports it, decentralization (no servers),
censorship resistance, and, in the cover-seed mode, strong deniability and traffic-analysis
resistance.

**Does not, by itself:** hide your IP address (peers and the DHT see it; run over Tor/I2P or use
the multi-hop extension for that), fully hide metadata (the DHT is public and crawlable; Riptide
raises the cost with rotation, k-anonymity, and cover traffic but does not eliminate it), or
moderate content for you (that is the recipient's job, by design). See
[01-threat-model.md](01-threat-model.md) for the honest boundary.

## Document map

Read in order for the first pass; the foundation (00-03) binds everything after it.

| Doc | Title | What it defines |
|---|---|---|
| [00-overview.md](00-overview.md) | Architecture and principles | The layer cake, design principles, how the pieces fit |
| [01-threat-model.md](01-threat-model.md) | Threat model | Adversaries, goals, non-goals, the honest limits |
| [02-identity.md](02-identity.md) | Identity and key management | One-seed identity, derivation, prekeys, key transparency, safety numbers |
| [03-conventions.md](03-conventions.md) | Wire and crypto conventions | THE CONSTITUTION: versioning, KDF label registry, encodings, record formats, AEAD discipline, errors |
| [04-rendezvous.md](04-rendezvous.md) | Rendezvous and presence | Derived DHT ids, epochs, discovery, private presence (C2 discovery, C7) |
| [05-session.md](05-session.md) | Pairwise session | The handshake and the secretstream session, plus cover-seed (C2, C3) |
| [06-mailbox.md](06-mailbox.md) | Asynchronous mailbox | Store-and-forward messaging with a ratchet (C1) |
| [07-feed.md](07-feed.md) | Broadcast feed | Signed encrypted one-to-many, and the public wall (C4, C8) |
| [08-groups.md](08-groups.md) | Group rooms | Many-to-many with sender keys (C5) |
| [09-objects.md](09-objects.md) | Objects and links | Capability links, content-addressed drops, large transfers (C6) |
| [10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md) | Anti-abuse and privacy | Spam defenses, k-anonymity, cover traffic, multi-hop, covert channels (C10, C11) |
| [11-capabilities-required.md](11-capabilities-required.md) | Capabilities required | What SodiumXT and TorrentXT must expose to build Riptide |
| [12-conformance-vectors.md](12-conformance-vectors.md) | Conformance vectors | Known-answer vectors for derivations and record encodings |
| [13-open-questions.md](13-open-questions.md) | Open questions | The research agenda and unresolved design forks |
| [glossary.md](glossary.md) | Glossary | Terms and abbreviations |

## Building Riptide

Two meta-documents guide the implementation (they are not part of the numbered spec):

- [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md) - the phased build order, the upstream capability
  prerequisites, the test strategy, and the risk register.
- [CLAUDE.md](CLAUDE.md) - operational guidance and the hard-won OXT / LCB / FFI lesson list carried
  forward from the sibling extensions (Box2Dxt, ShowControl, TorrentXT, SodiumXT).

## The one-paragraph pitch

One ed25519 keypair is your name on two networks. Your contacts find you at a meeting point only
your shared secret can compute, in a swarm that looks like any other. Your words are sealed with
authenticated encryption before they touch the wire, and the wire is the same BitTorrent traffic
the world already runs. There is no server to seize, no directory to subpoena, no switch to flip.
