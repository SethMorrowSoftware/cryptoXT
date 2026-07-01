# Glossary

Terms and abbreviations used across the Riptide spec, alphabetized. Each entry ends with the
document (by filename) where the term is defined in full. Where a channel document (04-10) is
referenced but not yet written, the term is introduced in the foundation docs (00-03) that the
channel builds on; the filename given is the authoritative home once that document lands.

House style, as everywhere in this spec: ASCII only, no em-dashes (hyphens, commas, colons, and
parentheses instead).

## Terms

- **Adversary rung 1 (passive network observer):** an ISP, a coffee-shop sniffer, or an on-path
  tap that sees your traffic but does not join the DHT or the swarm. (01-threat-model.md)
- **Adversary rung 2 (platform / service censor):** an actor that wants to block the ability to
  communicate by dropping traffic, seizing a server, or compelling a provider; Riptide's
  decentralization targets this rung. (01-threat-model.md)
- **Adversary rung 3 (active DHT participant / Sybil):** runs many DHT nodes, can eclipse or
  censor a targeted key, log who queries it, and crawl the DHT to catalog activity.
  (01-threat-model.md)
- **Adversary rung 4 (swarm insider):** joins the swarms you use, sees peer lists and your IP, and
  can attempt active manipulation of peer-wire traffic. (01-threat-model.md)
- **Adversary rung 5 (global passive adversary with correlation):** observes large fractions of the
  network and correlates timing and volume across links; the hardest rung, which Riptide does not
  claim to defeat and only cover-seed and multi-hop even approach. (01-threat-model.md)
- **Associated data (AD):** the authenticated-but-not-encrypted bytes bound into an AEAD envelope,
  the canonical bencode of `{ e: epoch, q: seq, t: type }`, so a captured ciphertext cannot be
  replayed or reordered into another slot. (03-conventions.md, section 3.5.1)
- **Canonical bencode:** Riptide's structured-record serialization, a bencoded dictionary with keys
  sorted lexicographically by raw byte value, matching BitTorrent and BEP44 signing; written
  `bencode(x)`. (03-conventions.md, section 3.2)
- **Capability link:** a self-contained unlock link of the form `bt-secure://H#base64(K)` whose
  fragment carries the decryption key `K` (which never touches the network) for a content-addressed
  encrypted object addressed by `H`. (09-objects.md)
- **Carrier:** an L1 way of moving bytes on BitTorrent: a BEP44 DHT record (signed, ~1000 bytes), a
  BEP10 peer-wire extension message (arbitrary size), or an encrypted torrent (bulk).
  (00-overview.md, 03-conventions.md sections 3.7-3.8)
- **Chain key:** the ratcheting symmetric secret a mailbox session holds; `sxKdfDerive` under
  context `rp-ratch` and the message counter turns it into the next chain key plus this message's
  message key. (06-mailbox.md, KDF label in 03-conventions.md section 3.4)
- **Cover-seed:** the strongest deniability mode, in which both parties genuinely seed a real,
  lawful torrent and tunnel the conversation inside that peer connection's BEP10 extension messages,
  so an observer sees ordinary file sharing. (05-session.md)
- **Cover traffic:** decoy swarm participation and decoy cells you write but never read, so real
  activity hides inside a baseline of noise and traffic analysis is harder.
  (10-anti-abuse-and-privacy.md)
- **Envelope:** the byte format of one protected message; a structured envelope is a bencode dict
  whose ciphertext lives in a byte-string field `c`, in one of the four shapes below.
  (03-conventions.md, section 3.5)
- **Envelope, sealed:** an anonymous-sender envelope, `c = sxSeal(pad(m), recipientPub)`, used for a
  first mailbox message so the sender is hidden even from the recipient. (03-conventions.md, 3.5)
- **Envelope, boxed:** an authenticated-sender envelope, `c = sxBox(pad(m), recipientPub,
  senderSec)`, where the sender's public key is conveyed out of band, never trusted from the
  envelope alone. (03-conventions.md, 3.5)
- **Envelope, AEAD:** a symmetric envelope with binding, `c = sxAeadEncrypt(pad(m), ad, key)`, where
  `ad` is the associated data of 3.5.1. (03-conventions.md, 3.5)
- **Envelope, stream (stream frame):** a live-session secretstream chunk from `sxSecretStreamPush`,
  framed as a 1-byte subtype plus payload inside a BEP10 message. (03-conventions.md, 3.5 and 3.8)
- **Epoch:** the shared time index `floor(unixTimeSeconds / EPOCH_SECONDS)` that rotates derived
  ids and keys; `EPOCH_SECONDS` defaults to 3600 (one hour) for rendezvous and presence.
  (03-conventions.md, section 3.9)
- **Epoch clock:** the wall-clock-derived counter that produces the epoch; parties SHOULD also check
  the adjacent epochs (`epoch-1`, `epoch+1`) to tolerate drift, and MUST agree on `EPOCH_SECONDS`
  for a channel. (03-conventions.md, section 3.9)
- **Feed:** a decentralized, authenticated, encrypted one-to-many broadcast (an un-censorable
  channel), a BEP44 mutable signed index over encrypted torrents, keyed by the publisher's identity
  under salt `rp-feed`. (07-feed.md)
- **G1 Confidentiality:** message content is readable only by intended recipients, provided by
  authenticated encryption (rungs 1-4). (01-threat-model.md)
- **G2 Integrity and authenticity:** tampering, forgery, and wrong keys are detected and rejected,
  never silently accepted (rungs 1-4). (01-threat-model.md)
- **G3 Forward secrecy:** compromise of a long-term key does not retroactively decrypt past messages
  that used ratcheted or ephemeral keys, where the channel supports it (rungs 1-4).
  (01-threat-model.md)
- **G4 Replay and reorder resistance:** a captured ciphertext cannot be replayed or reordered
  undetected, because epoch and sequence are bound as AD and BEP44 seq is monotonic (rungs 1-4).
  (01-threat-model.md)
- **G5 Censorship resistance:** there is no chokepoint to seize; redundancy and rotation raise the
  cost of eclipsing a key (rung 2, rung 3 with effort). (01-threat-model.md)
- **G6 Deniability:** the existence of a conversation is hidden inside a real, lawful BitTorrent
  transfer (cover-seed mode, rungs 1, 2, 4). (01-threat-model.md)
- **G7 Sender anonymity:** a sealed-box message does not reveal who sent it, even to the recipient,
  unless the sender chooses to sign (mailbox, objects). (01-threat-model.md)
- **Identity encryption key (IK_x):** your identity X25519 keypair, derived at KDF id 1 under
  context `rp-ident`, that others use to `sxBox`/`sxSeal` to you. (02-identity.md, section 2.2)
- **Identity key (IK):** your identity ed25519 signing keypair, derived at KDF id 0 under context
  `rp-ident`; it is your name, your DHT identity, and your BEP44 record-signing key. (02-identity.md,
  section 2.2)
- **Inbox id:** the derived, unguessable-until-you-know-the-pubkey 20-byte DHT id where mailbox
  messages for a recipient land, `inboxId = sxHash(recipientIK_x & be64(counter) & "rp-mbxid", 20)`.
  (06-mailbox.md, derivation form in 03-conventions.md section 3.4)
- **k-anonymous inbox:** an inbox addressed by a bucket prefix shared by a set of recipients who all
  fetch it and trial-decrypt, so who you write to is hidden inside an anonymity set.
  (10-anti-abuse-and-privacy.md)
- **Key-exchange key (KX):** your crypto_kx keypair, derived at KDF id 2 under context `rp-ident`,
  used for session key agreement via `sxKeyExchange*`. (02-identity.md, section 2.2)
- **Key-transparency log (identity log):** an append-only, hash-chained, ed25519-signed log of a
  contact's key changes, published as a BEP44 mutable seq-chain under `IK_pub` with salt `rp-idlog`,
  so a silent key substitution becomes detectable. (02-identity.md, section 2.6)
- **Master seed (S):** the 32-byte root secret from `sxRandomBytes(32)` from which every Riptide key
  derives; the only thing a user must back up, and its loss is unrecoverable (N5). (02-identity.md,
  section 2.1)
- **Message key:** the single-use symmetric key that encrypts one mailbox message, derived alongside
  the next chain key from the current chain key by the ratchet. (06-mailbox.md, KDF label in
  03-conventions.md section 3.4)
- **Multi-hop relay:** the speculative IP-privacy extension that onion-wraps a message in nested
  sealed boxes, each addressed to a relay key, so the write to a recipient's inbox does not come
  from your address; an open research track, not a finished guarantee.
  (10-anti-abuse-and-privacy.md)
- **N1 No IP anonymity by default:** peers and DHT nodes learn your IP; mitigate with a Tor/I2P
  underlay or the multi-hop extension. (01-threat-model.md)
- **N2 Incomplete metadata privacy:** the DHT is public, so rotation, k-anonymity, padding, and
  cover traffic raise the cost of linking and enumeration but do not eliminate it.
  (01-threat-model.md)
- **N3 No defense against a global passive adversary (rung 5):** traffic-confirmation by an
  omniscient observer is out of scope beyond what cover-seed and multi-hop approximate.
  (01-threat-model.md)
- **N4 No content moderation:** Riptide authenticates who said something so recipients can decide
  whom to trust; it does not filter content centrally. (01-threat-model.md)
- **N5 No recovery of a lost master seed:** no server means no reset; backup and social recovery are
  a design responsibility, not a safety net Riptide provides. (01-threat-model.md)
- **N6 Endpoint security is assumed:** a compromised device exposes keys and plaintext, and
  script-managed secrets cannot be locked or wiped. (01-threat-model.md)
- **N7 Availability is best-effort:** DHT churn, eclipse, and swarm death can delay or block
  delivery; Riptide favors confidentiality and integrity over guaranteed delivery.
  (01-threat-model.md)
- **One-time prekey (OPK):** a single-use X25519 keypair from a published batch, each consumed by
  exactly one sender and never reused, giving the strongest per-message one-time-key guarantee.
  (02-identity.md, section 2.4)
- **Phantom swarm:** a live encrypted 1:1 session held in a DHT rendezvous swarm that has no real
  torrent behind it; the swarm membership is the channel and the torrent is a MacGuffin.
  (05-session.md)
- **Prekey bundle:** the recipient's published set of a signed prekey, its `IK`-signature, and a
  batch of one-time prekeys, put as a BEP44 mutable record under `IK_pub` with salt `rp-prekeys`, so
  a sender can message you offline with forward secrecy from the first message. (02-identity.md,
  section 2.4)
- **Presence id:** a per-contact, per-epoch 20-byte DHT id (derived under context `rp-prsnc`) that
  you announce only while online, so a contact who can derive it sees you are reachable and nobody
  else can. (04-rendezvous.md, KDF label in 03-conventions.md section 3.4)
- **Ratchet:** the mailbox key schedule that advances the chain key one step per message via
  `sxKdfDerive` under context `rp-ratch`, yielding forward secrecy without extra round trips.
  (06-mailbox.md)
- **Rendezvous id:** a rotating, unguessable 20-byte DHT meeting id derived from a shared secret and
  the epoch (context `rp-rndzv`), where contacts announce and get_peers to discover each other.
  (04-rendezvous.md, KDF label in 03-conventions.md section 3.4)
- **Room key:** the shared secret of a group room from which each member's sender key is derived
  (context `rp-sendr`, member index) and at which the room rendezvous is computed. (08-groups.md,
  KDF label in 03-conventions.md section 3.4)
- **Safety number (SN):** an out-of-band fingerprint, `SN = sxHash(min(aIK, bIK) & max(aIK, bIK),
  32)`, rendered as words or a QR and compared with `sxMemEqual` at first contact to defeat a
  man-in-the-middle; sorting the keys makes it symmetric. (02-identity.md, section 2.5)
- **Sender key:** a per-member group key `SK_i = sxKdfDerive(roomKey, memberIndex, rp-sendr)` that
  authenticates that member's messages, letting members be added or removed by re-deriving keys.
  (08-groups.md)
- **Signed prekey (SPK):** a medium-term X25519 keypair, rotated on a schedule (for example weekly),
  whose public key is signed by `IK` (`spk_sig`) to prove it belongs to you. (02-identity.md,
  section 2.4)
- **Wall (public authenticated wall):** a decentralized, signed, non-secret but unforgeable public
  feed (an un-de-platformable microblog), a BEP44 mutable seq-chain under salt `rp-wall`; trust the
  key, not the host. (07-feed.md)

## BitTorrent BEPs Riptide uses

Reference to the BitTorrent Enhancement Proposals Riptide rides. See 03-conventions.md (carriers)
and 11-capabilities-required.md (what TorrentXT must expose).

| BEP | Name | One-line role in Riptide |
|---|---|---|
| BEP3 | The BitTorrent protocol (core) | The base torrent and swarm mechanics that carry bulk encrypted payloads and cover traffic. |
| BEP5 | DHT protocol | The Kademlia DHT `announce_peer` / `get_peers` used for rendezvous and presence on derived 20-byte ids. |
| BEP9 | Extension for peers to send metadata files | Metadata exchange, noted as a low-bandwidth covert carrier. |
| BEP10 | Extension protocol | The peer-wire extension framing (`rp1`) that carries live sessions and the cover-seed tunnel. |
| BEP11 | Peer exchange (PEX) | Peer-exchange gossip usable as a flood/gossip bus for group messages. |
| BEP15 | UDP tracker protocol | The UDP tracker transport for finding swarm peers. |
| BEP44 | Storing arbitrary data in the DHT | Signed mutable (keyed by pubkey + salt + seq) and hash-addressed immutable records: the mailbox, prekey, feed, and log carrier. |
| BEP52 | BitTorrent protocol v2 | The v2 torrent format (SHA-256 addressing) for encrypted-object transfers. |

## libsodium / SodiumXT primitives

The cryptographic building blocks Riptide composes (it adds no cryptography of its own). See
03-conventions.md section 3.3 for the full table and sizes.

| Primitive | One-line description | SodiumXT handler |
|---|---|---|
| ed25519 | Signature scheme for identity, BEP44 record signing, and the key-transparency log. | `sxSign` / `sxSignDetached` / `sxSignVerifyDetached` / `sxSignKeypairFromSeed` |
| X25519 | Elliptic-curve Diffie-Hellman key underlying the box, seal, and kx primitives. | (via the box/kx/seal calls below) |
| crypto_box | Authenticated public-key encryption (X25519 + XSalsa20-Poly1305), nonce prepended. | `sxBox` / `sxBoxOpen` |
| crypto_box_seal | Anonymous-sender public-key encryption (sealed box), 48-byte overhead. | `sxSeal` / `sxSealOpen` |
| crypto_kx | Key agreement that yields directional session keys from a keypair exchange. | `sxKeyExchange*` (client/server) / `sxKeyExchangeKeypair` |
| XChaCha20-Poly1305 | Symmetric AEAD with a 24-byte nonce (prepended) and a 16-byte tag, for bound envelopes. | `sxAeadEncrypt` / `sxAeadDecrypt` |
| secretstream | Streaming AEAD (XChaCha20-Poly1305) with per-chunk auth, ordering, and a FINAL truncation-detecting tag. | `sxSecretStream*` (InitPush / Push / Pull) |
| Argon2id | Memory-hard password hashing / passphrase-to-key derivation (at-rest seed wrapping). | `sxPwHash` (with `sxPwMemModerate` and friends) |
| BLAKE2b | Fast cryptographic hash for ids, safety numbers, and hash chains (16..64-byte output). | `sxHash` / `sxHashKeyed` |
| crypto_kdf | BLAKE2b key-derivation function: 32-byte master, 8-byte context, uint64 id, for all subkeys. | `sxKdfDerive` |

Also referenced: XSalsa20-Poly1305 secretbox (`sxSecretBox` / `sxSecretBoxOpen`), a symmetric cipher
with no associated data; the CSPRNG (`sxRandomBytes` / `sxRandomUniform`); padding (`sxPad` /
`sxUnpad`); constant-time comparison (`sxMemEqual`); and base64 (`sxBin2Base64`). (03-conventions.md,
section 3.3)
