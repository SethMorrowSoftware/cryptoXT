# SodiumXT API reference

The complete `sx*` handler surface (library `org.openxtalk.library.sodium`), as called from
LiveCode Script.

New to SodiumXT? Start with [getting-started.md](getting-started.md) for setup and the calling
conventions, then [recipes.md](recipes.md) for end-to-end examples and
[security.md](security.md) for the rules that keep your data safe.

## Conventions you need before calling anything

- **Bytes cross as `Data`; text crosses as `String`.** Keys, nonces, ciphertext,
  digests, salts, signatures: all `Data`. Pass a passphrase or message you have as
  text through `textEncode(theText, "utf-8")` to get the `Data` the API wants, and
  `textDecode(theData, "utf-8")` to turn recovered plaintext back into text.
- **Hex / base64 / the pwhash string come back as `Data`** (the ASCII bytes), not
  `String`. `textDecode(..., "ascii")` if you want a `String` to display or store.
- **Functions return a value; `nothing`-returning handlers are commands.** Call a
  function as `put sxHash(d, 32) into x`. Call a command as `sxEncryptFile a, b, k`.
- **`out` parameters are by reference (pass a variable).** Command form:
  `sxBoxKeypair tPk, tSk`. Inside a function call:
  `put sxSecretStreamInitPush(tKey, tHeader) into tHandle` (fills `tHeader`).
- **Failure throws.** Authentication failures (wrong key, tampered data, bad
  signature), bad lengths, and I/O errors `throw`; wrap calls that can fail in
  `try ... catch`. The thrown message is prefixed with the handler name; the last
  native message is also available via `sxLastError()`.
- **Never compare secrets with `is` / `=`.** Use `sxMemEqual` (constant time).
- **Never reuse a nonce with a key.** The one-shot calls draw and prepend a random
  nonce for you; secretstream derives per-chunk nonces from a random header. There
  is no bring-your-own-nonce entry point, by design.

## Init and diagnostics

| Handler | Returns | Notes |
|---|---|---|
| `sxInit()` | command | Optional. Every handler self-initializes libsodium and checks the ABI on first use; call this only to fail fast at startup. Throws on an ABI mismatch or a failed init. |
| `sxVersion()` | `String` | e.g. `SodiumXT 0.1.0 (libsodium 1.0.20)`. |
| `sxLastError()` | `String` | The last native error message on this thread, or empty. |

## Randomness

| Handler | Returns | Notes |
|---|---|---|
| `sxRandomBytes(pCount)` | `Data` | `pCount` cryptographically secure random bytes. The only sanctioned source of salts, nonces, and keys. Never use the engine `random()` for anything unguessable. |
| `sxRandomUniform(pUpperBound)` | `Integer` | Unbiased random integer in `[0, pUpperBound)` (no modulo skew). `pUpperBound` >= 1. |

## Hashing, encoding, constant-time compare

BLAKE2b. The default digest length is 32 bytes; the valid range is 16..64.

| Handler | Returns | Notes |
|---|---|---|
| `sxHash(pData, pOutLen)` | `Data` | Unkeyed BLAKE2b digest of `pData`, `pOutLen` bytes. |
| `sxHashKeyed(pData, pKey, pOutLen)` | `Data` | Keyed BLAKE2b (a MAC / domain-separated hash). |
| `sxHashFile(pPath, pOutLen)` | `Data` | BLAKE2b of a whole file, read chunk-by-chunk C-side: the bytes never enter a `Data`, so a multi-gigabyte file hashes without blowing up memory. `pPath` is a UTF-8 file path. |
| `sxHashFileKeyed(pPath, pKey, pOutLen)` | `Data` | Keyed file hash (a file MAC). |
| `sxBin2Hex(pData)` | `Data` | Lowercase hex of `pData` (ASCII bytes). |
| `sxHex2Bin(pHex)` | `Data` | Decode hex (`Data` of ASCII hex) back to bytes; throws on malformed input. |
| `sxBin2Base64(pData)` | `Data` | URL-safe base64, no padding (ASCII bytes). |
| `sxBase642Bin(pB64)` | `Data` | Decode URL-safe base64 back to bytes; throws on malformed input. |
| `sxMemEqual(pA, pB)` | `Boolean` | Constant-time equality. The only sanctioned way to compare a MAC, tag, hash, or any secret. |

### Multipart hash (data assembled incrementally)

Open a state, feed chunks, finalize. `sxHashFinal` writes the digest and releases
the handle (so the common path self-cleans); call `sxFreeHash` only to abandon a
state you will not finalize. Pass the same `pOutLen` to init and final.

| Handler | Returns | Notes |
|---|---|---|
| `sxHashInit(pOutLen)` | `Integer` | Open an unkeyed multipart hash; returns a handle. |
| `sxHashInitKeyed(pKey, pOutLen)` | `Integer` | Open a keyed multipart hash. |
| `sxHashUpdate(pHandle, pData)` | command | Fold more bytes in. |
| `sxHashFinal(pHandle, pOutLen)` | `Data` | Produce the digest and release the handle. |
| `sxFreeHash(pHandle)` | command | Abandon a state without finalizing (idempotent). |

```
local tH, tDigest
put sxHashInit(32) into tH
sxHashUpdate tH, textEncode("part one ", "utf-8")
sxHashUpdate tH, textEncode("part two", "utf-8")
put sxHashFinal(tH, 32) into tDigest   -- 32-byte BLAKE2b-256 of the whole stream
```

## Passwords and key derivation (Argon2id, KDF)

`opslimit` and `memlimit` cross as **decimal Strings** (a memlimit can exceed 2^31).
Use the presets below for the memlimit, and the matching opslimit literal: `"2"`
(interactive), `"3"` (moderate), `"4"` (sensitive). Always store the salt (and the
ops/mem you used) alongside the ciphertext so you can re-derive, and raise the cost
later without breaking old data.

| Handler | Returns | Notes |
|---|---|---|
| `sxPwMemInteractive()` | `String` | Memlimit preset (fast; interactive logins). |
| `sxPwMemModerate()` | `String` | Memlimit preset (moderate). |
| `sxPwMemSensitive()` | `String` | Memlimit preset (slow; high-value secrets). |
| `sxPwHash(pPassphrase, pSalt, pKeyLen, pOpsLimit, pMemLimit)` | `Data` | Derive a `pKeyLen`-byte key from a passphrase (`Data`; textEncode it) and a `pSalt` (16 random bytes from `sxRandomBytes`). |
| `sxPwHashStr(pPassphrase, pOpsLimit, pMemLimit)` | `Data` | Self-describing hash string for storage (packs salt + cost); ASCII bytes. |
| `sxPwHashStrVerify(pHash, pPassphrase)` | `Boolean` | Verify a passphrase against a stored `sxPwHashStr` string (pass the stored hash as a `String`). Constant time. |
| `sxKdfDerive(pMasterKey, pSubkeyId, pContext, pSubkeyLen)` | `Data` | Derive subkey number `pSubkeyId` (a decimal `String`) from a master key, namespaced by an 8-byte `pContext`. |

## Secret-key authenticated encryption

A random nonce is generated and **prepended** for you; output is `nonce ||
ciphertext || MAC`. Open throws on a wrong key or any tampering (it never returns
garbage).

| Handler | Returns | Notes |
|---|---|---|
| `sxSecretBox(pMessage, pKey)` | `Data` | Encrypt `pMessage` under a 32-byte `pKey` (XSalsa20-Poly1305). |
| `sxSecretBoxOpen(pBox, pKey)` | `Data` | Decrypt; throws on wrong key / tamper. |
| `sxAeadEncrypt(pMessage, pAd, pKey)` | `Data` | Like secretbox, but also authenticates associated data `pAd` (not encrypted, e.g. a header). XChaCha20-Poly1305 IETF. |
| `sxAeadDecrypt(pBox, pAd, pKey)` | `Data` | Decrypt; throws if the ciphertext OR the supplied `pAd` does not match what was sealed. |

```
local tSalt, tKey, tBox
put sxRandomBytes(16) into tSalt
put sxPwHash(textEncode(field "pass", "utf-8"), tSalt, 32, "2", sxPwMemInteractive()) into tKey
put sxSecretBox(textEncode(field "msg", "utf-8"), tKey) into tBox
-- store base64(tSalt & tBox); on open, split off the 16-byte salt and re-derive tKey
```

## Streaming AEAD (secretstream) and whole-file encryption

For data too large to hold twice in memory. The FINAL tag on the last chunk makes
truncation detectable. You must free what you open (`sxFreeStream`); there is no
deterministic unload hook.

| Handler | Returns | Notes |
|---|---|---|
| `sxSecretStreamInitPush(pKey, out rHeader)` | `Integer` | Open an encrypt stream; returns a handle and fills `rHeader` (store/send it). |
| `sxSecretStreamPush(pHandle, pChunk, pAd, pFinal)` | `Data` | Encrypt one chunk; pass `true` for `pFinal` on the LAST chunk. `pAd` may be empty. |
| `sxSecretStreamInitPull(pKey, pHeader)` | `Integer` | Open a decrypt stream from the header; returns a handle. |
| `sxSecretStreamPull(pHandle, pCipherChunk, pAd, out rTag)` | `Data` | Decrypt one chunk; fills `rTag`. Throws on wrong key / tamper. |
| `sxIsFinalTag(pTag)` | `Boolean` | True if `rTag` is the FINAL tag (the stream ended cleanly). |
| `sxFreeStream(pHandle)` | command | Release a stream handle (idempotent). |
| `sxEncryptFile(pSrcPath, pDstPath, pKey)` | command | Encrypt a file entirely C-side (bytes never enter a `Data`). Throws on I/O error. |
| `sxDecryptFile(pSrcPath, pDstPath, pKey)` | command | Decrypt; throws on a wrong key or a truncated/corrupt input. |

## Public-key encryption (X25519)

| Handler | Returns | Notes |
|---|---|---|
| `sxBoxKeypair(out rPublicKey, out rSecretKey)` | command | Generate an X25519 keypair. |
| `sxBox(pMessage, pRecipientPk, pSenderSk)` | `Data` | Authenticated encryption from sender to recipient (random nonce prepended). |
| `sxBoxOpen(pBox, pSenderPk, pRecipientSk)` | `Data` | Open; throws on wrong key / tamper. |
| `sxSeal(pMessage, pRecipientPk)` | `Data` | Anonymous-sender sealed box (sender needs only the recipient's public key). |
| `sxSealOpen(pSealed, pRecipientPk, pRecipientSk)` | `Data` | Open a sealed box with the recipient's full keypair. |

## Signatures (ed25519)

| Handler | Returns | Notes |
|---|---|---|
| `sxSignKeypair(out rPublicKey, out rSecretKey)` | command | Random ed25519 keypair. |
| `sxSignKeypairFromSeed(pSeed, out rPublicKey, out rSecretKey)` | command | Deterministic keypair from a 32-byte seed (BEP44-compatible). |
| `sxSignDetached(pMessage, pSecretKey)` | `Data` | A detached signature (verify alongside the message). |
| `sxSignVerifyDetached(pSig, pMessage, pPublicKey)` | `Boolean` | True if the signature is valid (never throws; a bad signature is `false`). |
| `sxSign(pMessage, pSecretKey)` | `Data` | Attached signature (signature + message in one blob). |
| `sxSignOpen(pSignedMessage, pPublicKey)` | `Data` | Recover the message, or throw if the signature does not verify. |

## Key exchange (crypto_kx)

Each side derives the SAME pair of session keys: the client's rx equals the
server's tx and vice versa. rx is for receiving, tx for sending.

| Handler | Returns | Notes |
|---|---|---|
| `sxKeyExchangeKeypair(out rPublicKey, out rSecretKey)` | command | An X25519 kx keypair. |
| `sxKeyExchangeClient(pClientPk, pClientSk, pServerPk, out rRx, out rTx)` | command | The client derives its session keys. Throws if the peer key is rejected. |
| `sxKeyExchangeServer(pServerPk, pServerSk, pClientPk, out rRx, out rTx)` | command | The server derives its session keys. |

## Padding (length hiding)

| Handler | Returns | Notes |
|---|---|---|
| `sxPad(pData, pBlockSize)` | `Data` | Append 1..`pBlockSize` padding bytes so the length is a multiple of `pBlockSize` (hides the exact message length before encryption). |
| `sxUnpad(pData, pBlockSize)` | `Data` | Recover the original bytes; throws on malformed padding. |

## See also

- `examples/sodium-tests.livecodescript` - `put sxSelfTest()` exercises every handler.
- `examples/sodium-demo.livecodescript` - an interactive, tabbed showcase (Secret Key, Public
  Key, Signatures, Hash & Files, About), with a "Run the full self-test" button on the About tab.
