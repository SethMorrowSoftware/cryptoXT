# 12. Conformance vectors

Known-answer vectors that pin Riptide's deterministic derivations and encodings to fixed outputs, so
independent implementations can prove they agree byte for byte. Every value below was computed
against the pinned **libsodium 1.0.20** through the SodiumXT shim; the generator is reproduced at the
end so anyone can regenerate them.

Only **deterministic** constructions can be conformance-tested this way. Sealed, boxed, and AEAD
envelopes (`sxSeal`, `sxBox`, `sxAeadEncrypt`) each draw a fresh random nonce, so their ciphertext is
non-deterministic by design (nonce discipline, [03-conventions.md](03-conventions.md) section 3.3);
they are validated by round-trip and tamper tests, not by KAT. What is pinned here: the KDF
derivations, the BLAKE2b id/hash derivations, the ed25519 identity key from a seed, and the ed25519
BEP44 signature (ed25519 signing is deterministic).

All byte strings are shown in lowercase hex. Contexts and salts are ASCII.

## 12.1 Identity derivation (doc 02, label `rp-ident`)

Fixed test master seed `S` = the 32 bytes `00 01 02 ... 1f`.

```
S       = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
edSeed  = sxKdfDerive(S, id=0, context="rp-ident", outlen=32)
        = cac73f09a0478224974a525036ebd73f9727ac8932162eb7fcfb2821ad7eecc7
IK_pub  = sxSignKeypairFromSeed(edSeed).publicKey
        = 672e8e0b259627f15c772ec0d61f15cd786ce2bc7244549255f9d6cfaac300b2

boxSeed = sxKdfDerive(S, id=1, context="rp-ident", outlen=32)
IK_x_pub = sxBoxKeypairFromSeed(boxSeed).publicKey
        = 5b9d094b6c0de5c16b3605cffd6d056144384855f82d02c352c5cffd3b60bf65
kxSeed  = sxKdfDerive(S, id=2, context="rp-ident", outlen=32)
KX_pub  = sxKeyExchangeKeypairFromSeed(kxSeed).publicKey
        = 4a9789d887a6dcb2246f1a03833dab4c6c77c57633caef004190ba5f990a3d35
```

`IK_pub` is the identity's name and the key under which its BEP44 records live; `IK_x_pub` and
`KX_pub` are the encryption keys others use to reach you. All three derive from the one master seed
`S` via the seeded-keypair calls SodiumXT added at ABI 5 (see [02-identity.md](02-identity.md)
section 2.2 and [11-capabilities-required.md](11-capabilities-required.md)), so one backup blob
reconstructs the whole identity.

## 12.2 Rendezvous id (doc 04, label `rp-rndzv`)

Fixed test shared secret `ss` = `0x42` repeated 32 times; epoch = `471000`.

```
ss   = 4242424242424242424242424242424242424242424242424242424242424242
rid  = sxKdfDerive(ss, id=471000, context="rp-rndzv", outlen=20)
     = 8d28959919bb0118762ea0c0b74d4ed7b216fc6f
```

`rid` is the 20-byte DHT id both parties announce to for that epoch.

## 12.3 Presence id (doc 04, label `rp-prsnc`)

Same `ss` and epoch as 12.2, different context, so a distinct id:

```
pid  = sxKdfDerive(ss, id=471000, context="rp-prsnc", outlen=20)
     = e49c0e9369ac8e1a67de21abf2d9fe5f2304fdf2
```

That `rid` and `pid` differ despite identical inputs demonstrates the context's domain separation.

## 12.4 Inbox id (doc 06)

Derived from a public key, so BLAKE2b (`sxHash`) with the domain tag `rp-mbxid`, not the KDF. Fixed
test recipient key `IK_x` = `0x33` repeated 32 times; counter = 7 (as 8 big-endian bytes).

```
input   = IK_x (32) || be64(7) || "rp-mbxid"
        = 3333...33 || 0000000000000007 || 72702d6d62786964
inboxId = sxHash(input, outlen=20)
        = 5b2db5b4b23a3f72ec7ab7bab4a730cc009e62d6
```

## 12.5 Safety number (doc 02, section 2.5)

Fixed test identity keys `a` = `0xAA` x32, `b` = `0xBB` x32. Keys are sorted so both parties compute
the same value; here `a < b`, so the input is `a || b`.

```
SN = sxHash(min(a,b) || max(a,b), outlen=32)
   = e4351a237b5150f780837f4ef69b4feb9496b48780cb07a8193803840e71a17c
```

A client renders `SN` as a word list or QR for out-of-band comparison.

## 12.6 BEP44 mutable signature (doc 03 section 3.7, doc 07)

The most important interop vector: a Riptide-produced ed25519 signature must validate as a BEP44
signature in any conformant DHT. Using the identity of 12.1 (`edSeed` -> `IK`), a record with salt
`rp-prekeys`, `seq` = 1, and bencoded value `2:hi`, the BEP44 signing buffer (section 3.7) is the
ASCII string:

```
sign buffer = 4:salt10:rp-prekeys3:seqi1e1:v2:hi
sig         = sxSignDetached(signBuffer, IK_secretKey)
            = 86c843ec4cc2495e025e949dd72658ef01556dbbfb1f5d9b474b5957dbcb26a2
              3497efe40f594387cc4f037075669efa4c42cb57c007eb0bddaa24934f3f740b
verify      = sxSignVerifyDetached(sig, signBuffer, IK_pub) = 1
```

The signature is 64 bytes (shown wrapped). It verifies against `IK_pub` from 12.1, and, because
ed25519 is deterministic, any correct implementation produces exactly these bytes.

## 12.7 Non-deterministic constructions (validate by property, not KAT)

These have no fixed output and are tested differently:

| Construction | Why non-deterministic | Test instead |
|---|---|---|
| `sxSeal` / `sxBox` / `sxAeadEncrypt` | fresh random nonce prepended | round-trip opens; a flipped byte fails to open (SXT_ERR_AUTH) |
| `sxSecretStream` session | random header, per-chunk nonces | multi-chunk round-trip; truncated stream fails (FINAL tag) |
| prekeys, ephemeral keys | fresh random keypairs | handshake agrees the same session key on both sides |
| PoW nonce (doc 10) | search over random nonces | the difficulty check holds for the found nonce |

## 12.8 Regenerating these vectors

The vectors were produced by linking the SodiumXT shim against the pinned libsodium and calling the
same `sxt_*` entry points the LCB layer wraps. To reproduce (from the repo root, after a
`cmake -S . -B build -DSODIUMXT_BUILD_TESTS=ON` so `build/libsodium/install` exists):

```
gcc -std=c11 -I src -isystem build/libsodium/install/include \
    vectors.c src/sodium_shim.c build/libsodium/install/lib/libsodium.a -o vectors && ./vectors
```

where `vectors.c` calls, with the fixed inputs above: `sxt_kdf_derive` (contexts `rp-ident`,
`rp-rndzv`, `rp-prsnc`), `sxt_sign_keypair_from_seed`, `sxt_generichash` (inbox id, safety number),
and `sxt_sign_detached` / `sxt_sign_verify_detached` (the BEP44 signature). The exact program used to
generate this document is small and should be checked into a future `riptide/vectors/` alongside a
test that asserts these outputs, so a libsodium version bump that changed any of them would fail CI
(the same discipline the C smoke test uses for its own KATs).

## 12.9 A note on stability

If the pinned libsodium version changes, re-run the generator and update any vector that moves. KDF,
BLAKE2b, and ed25519 outputs are stable across the libsodium 1.0.x line for fixed inputs, so these
vectors are expected to hold; the regeneration step is the guard against a silent change.
