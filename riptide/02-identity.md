# 02. Identity and key management

Everything in Riptide hangs off one secret. This document defines how that secret becomes the set of
keys the protocol uses, how contacts learn and verify each other's public keys, and how key changes
are made tamper-evident.

## 2.1 The master seed

A Riptide identity is a **32-byte master seed**, `S`, from `sxRandomBytes(32)`. It is the only thing
a user must back up, and its loss is unrecoverable (threat-model N5). All other keys derive from it,
so the whole identity is one backup blob.

Storage is out of scope for the wire protocol but in scope for a client: at rest, wrap `S` under a
passphrase-derived key, `sxSecretBox(S, sxPwHash(passphrase, salt, 32, "3", sxPwMemModerate()))`,
and store the salt beside it.

## 2.2 Key derivation

All subkeys derive from `S` with the BLAKE2b KDF (`sxKdfDerive`), which takes a 32-byte master key,
an 8-byte context, and a uint64 id. `S` is the master key. The context for identity derivation is
the 8-byte ASCII string `rp-ident` (see the label registry in [03-conventions.md](03-conventions.md)).

| id | Derives | Length | Becomes |
|---|---|---|---|
| 0 | ed25519 seed | 32 | identity signing keypair `IK` via `sxSignKeypairFromSeed` |
| 1 | X25519 seed | 32 | identity encryption keypair `IK_x` (box) |
| 2 | kx seed | 32 | key-exchange keypair `KX` via crypto_kx |

```
edSeed = sxKdfDerive(S, "0", <"rp-ident">, 32)
sxSignKeypairFromSeed edSeed -> IK_pub (32), IK_sec (64)     -- your name and DHT identity
```

**Capability status: available (SodiumXT ABI 5).** All three keys derive deterministically from `S`:
`sxSignKeypairFromSeed` for the signing key (id 0), and the seeded-keypair calls
`sxBoxKeypairFromSeed` (id 1) and `sxKeyExchangeKeypairFromSeed` (id 2) for the encryption keys, added
to SodiumXT for exactly this purpose ([11-capabilities-required.md](11-capabilities-required.md)). One
master seed therefore reconstructs the whole identity; no separate keypair storage is required. All
three ids are pinned in the conformance vectors ([12-conformance-vectors.md](12-conformance-vectors.md)).

## 2.3 Public identity

Your public identity, shared with contacts and published to the DHT, is:

```
IdentityCard = { v: 1, ik_ed: IK_pub, ik_x: IK_x_pub, kx: KX_pub }
```

bencoded per [03-conventions.md](03-conventions.md). `ik_ed` is your name (it keys your BEP44
records and the DHT); `ik_x` and `kx` are how others encrypt to you. A short, human-facing form of
the identity is `sxBin2Base64(IK_pub)` (URL-safe, no padding).

## 2.4 Prekeys and the prekey bundle

To let someone message you while you are offline with forward secrecy from the first message, you
publish a **prekey bundle**: a set of ephemeral X25519 public keys others can use once.

- **Signed prekey `SPK`:** a medium-term X25519 keypair, rotated on a schedule (for example weekly),
  whose public key is signed by `IK`.
- **One-time prekeys `OPK_i`:** a batch of single-use X25519 keypairs; each is consumed by one
  sender and never reused. Replenish the batch as they are used.

```
PrekeyBundle = {
  v: 1,
  ik_ed: IK_pub,
  ik_x:  IK_x_pub,
  spk:   SPK_pub,
  spk_sig: sxSignDetached(SPK_pub, IK_sec),      -- proves SPK belongs to IK
  opks:  [ OPK_0_pub, OPK_1_pub, ... ],          -- optional, may be empty
  exp:   <unix-epoch expiry>
}
```

The bundle is published as a **BEP44 mutable record** under `IK_pub` with salt `rp-prekeys` (record
format in [03-conventions.md](03-conventions.md)). Because BEP44 values are ~1000 bytes, a bundle
carries only a handful of one-time prekeys at a time; a sender who finds `opks` empty falls back to
`SPK` only (weaker one-time-key guarantees, still forward-secret via the ratchet). The handshake that
consumes a bundle is in [05-session.md](05-session.md) and [06-mailbox.md](06-mailbox.md).

## 2.5 Verifying a contact's identity (first contact)

The dangerous moment is the first time you learn a contact's `IK_pub`, because a rung-3 adversary
controlling the DHT lookup could hand you a key of their own. Two defenses, use at least one:

- **Safety number (out of band).** Both parties compute
  `SN = sxHash(min(aIK, bIK) & max(aIK, bIK), 32)` (identity keys sorted so both get the same value)
  and render it as a word list or QR. Compare in person or over an authenticated channel; accept only
  on match, checked with `sxMemEqual`. Sorting makes the number symmetric and order-independent.
- **Key-transparency log (2.6).** Follow the contact's append-only key log so any later substitution
  is detectable even if the first fetch was honest.

## 2.6 Key transparency: the identity log

A malicious DHT node can try to serve a stale or forged prekey bundle. Riptide makes key history
**append-only and self-authenticating** so substitution is detectable.

Each identity maintains a hash-chained, ed25519-signed log published as a BEP44 mutable seq-chain
under `IK_pub` with salt `rp-idlog`. Entry `n`:

```
LogEntry[n] = {
  seq:  n,
  prev: sxHash(canonical(LogEntry[n-1]), 32),    -- 0^32 for n = 0
  op:   "rotate-spk" | "add-opks" | "revoke" | "rekey" | ...,
  data: <op-specific, e.g. the new SPK and its signature>,
  ts:   <unix epoch>
}
sig = sxSignDetached(canonical(LogEntry[n]), IK_sec)
```

A follower caches the latest `(seq, hash)` it has verified. On refetch it requires `seq` to be
monotonic and `prev` to match its cached hash; a fork (two valid entries at the same `seq`, or a
broken `prev` link) is evidence of tampering or a compromised key and is surfaced to the user, not
silently accepted. This does not stop a compromise, but it makes a silent key swap loud.

A full transparency system (gossiped consistency proofs, witness co-signing) is an extension, noted
in [13-open-questions.md](13-open-questions.md); the self-chained log above is the buildable baseline.

## 2.7 Rotation and revocation

- **Signed prekey `SPK`** rotates on a schedule; publish the new `SPK` and a `rotate-spk` log entry.
- **One-time prekeys** are consumed and replenished; never reuse one.
- **Compromise** is signaled with a `revoke` / `rekey` log entry that names the retired key and, if
  the master seed is intact, is signed by `IK`. If `IK` itself is lost or compromised, recovery
  requires a pre-arranged out-of-band re-introduction; there is no server to appeal to (N5).
- **Contacts** react to a verified `revoke`/`rekey` by refusing the old keys and re-verifying (2.5).

## 2.8 What a client must persist

At minimum: the master seed `S` (encrypted at rest); the current `SPK` and unconsumed `OPK` secret
keys; each contact's last-verified `IK_pub` and their last-verified log `(seq, hash)`; and per-channel
session state (chain keys, counters) defined in the channel documents. Everything else is
recomputable from `S`.
