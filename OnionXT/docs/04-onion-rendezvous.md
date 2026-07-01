# 04 - Onion Rendezvous: the Address IS a Public Key

This is the idea that makes OnionXT more than "Tor for xTalk." A v3 onion address is not a name that
points at a key; it is the key, encoded. That gives self-authenticating rendezvous and a deterministic,
reproducible identity address, for free, by composing SodiumXT's ed25519.

## The v3 onion address format

A v3 `.onion` address is:

```
onion_address = base32( PUBKEY || CHECKSUM || VERSION ) + ".onion"

  PUBKEY   = the 32-byte ed25519 public key of the service
  VERSION  = 0x03  (one byte)
  CHECKSUM = first 2 bytes of  SHA3-256( ".onion checksum" || PUBKEY || VERSION )
```

- `32 + 2 + 1 = 35` bytes, base32-encoded (lowercase, no padding) = **56 characters**, then `.onion`.
- So `oxPublicKeyFromAddress` is just: strip `.onion`, base32-decode the 56 chars to 35 bytes, take the
  first 32 as the ed25519 public key. And `oxAddressFromPublicKey` is: `base32(pubkey || checksum ||
  0x03)`.

**Connecting to the address authenticates the key.** During the rendezvous, Tor verifies the service's
descriptor signature against the ed25519 key encoded in the address you dialed. You cannot be silently
connected to an impostor: an attacker would need the private key for that exact address. So a contact's
`.onion` doubles as a pinned public key, and first contact needs no separate, MITM-able key exchange.

## Composing SodiumXT: identity to address

The service's ed25519 key is exactly the kind of key SodiumXT already makes:

```
seed (32 bytes, from the app's master seed / passphrase via Argon2id)
  -> sxSignKeypairFromSeed  ->  ed25519 (public 32, secret)      [SodiumXT, deterministic]
  -> ed25519 public key      ->  oxAddressFromPublicKey  ->  <56>.onion
```

Because `sxSignKeypairFromSeed` is deterministic, the **same seed always yields the same `.onion`**.
An app can therefore:

- Recover its exact onion address after a reinstall from just the passphrase (nothing to back up),
  mirroring SodiumXT's deterministic-keypair story.
- Publish its onion address as its identity; a contact who has the address has the public key.
- Bind the address into a SodiumXT signature at first contact, so a swapped address is detected.

## The expanded-key gotcha (the single most likely thing to get wrong)

`ADD_ONION ED25519-V3:<key>` does **not** take a 32-byte seed and does **not** take libsodium's 64-byte
secret key (`seed || pubkey`). Tor wants the **expanded** ed25519 secret key: the 64-byte
`(scalar a || prefix RH)` that standard ed25519 derives internally by hashing the seed. Concretely:

```
h = SHA-512(seed)               # 64 bytes
a = h[0:32] with clamping:      # the scalar
      a[0]  &= 0xF8
      a[31] &= 0x7F
      a[31] |= 0x40
RH = h[32:64]                   # the nonce prefix
expanded_secret = a || RH       # 64 bytes; base64 this for ADD_ONION ED25519-V3:
```

This is the format Tor's own tools and the `stem` library produce, and getting it wrong is the classic
deterministic-onion bug (the address comes out different, or ADD_ONION rejects the key). Two ways to
get it right:

1. **Let Tor generate the key** (`NEW:ED25519-V3`) and persist the returned `PrivateKey`. Simplest;
   the address is then random, not seed-derived. Fine when reproducibility is not required.
2. **Compute the expansion yourself.** You need SHA-512 (to hash the seed) and then the clamping above.
   SodiumXT does not currently expose SHA-512 or an "ed25519 expanded key from seed" helper, so this is
   a capability gap (doc 08). The clean fix is a tiny SodiumXT addition, `sxSignSeedToExpandedKey` (or
   exposing `crypto_hash_sha512` plus doing the clamp in script), landed upstream first.

Do not hand-roll SHA-512 in script to dodge the gap; that violates "compose SodiumXT, add no crypto"
(CLAUDE.md rule 1). Land the upstream helper.

## The checksum and base32

- The address **checksum** needs SHA3-256, which SodiumXT also does not expose today (doc 08). But the
  checksum is only needed to *emit* a correct address and to *validate* a pasted one; you can defer both
  by getting your own address from `ADD_ONION`'s `ServiceID` (Tor computes it) and by trusting the
  connect-time descriptor-signature check rather than a local checksum verify. Add SHA3-256 upstream
  when you want offline `oxAddressFromPublicKey` / address validation.
- **base32** here is RFC 4648 lowercase without padding. It is pure byte manipulation; implement it in
  script (or a thin LCB helper if the on-engine pass shows it is a hot path). No crypto, no upstream
  dependency.

## Client authorization (optional, stronger rendezvous)

v3 onion services support **client authorization**: the service is only reachable by clients holding a
configured x25519 key, and its descriptor is encrypted to those clients. This turns the onion into a
private rendezvous that even someone who learns the address cannot reach. It composes SodiumXT x25519
keys (`sxKeyExchangeKeypair` / from-seed) and is configured via `ADD_ONION`'s `ClientAuthV3=` and the
matching client-side key. Treat it as a Phase 6+ enhancement: it upgrades rung-3 resistance (an
attacker who phishes the address still cannot connect) at the cost of a key-distribution step.

## Summary of the mapping

| Concept                     | Where it lives                                             |
|-----------------------------|-----------------------------------------------------------|
| ed25519 identity keypair    | SodiumXT `sxSignKeypair` / `sxSignKeypairFromSeed`        |
| seed -> expanded onion key  | SodiumXT helper (doc 08 gap) -> `ADD_ONION ED25519-V3:`  |
| pubkey <-> `.onion` address | OnionXT base32 (+ SHA3-256 checksum, doc 08 gap)         |
| address authenticates key   | Tor's descriptor-signature check at connect time         |
| private rendezvous          | v3 client authorization (SodiumXT x25519), optional      |
