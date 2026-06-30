# SodiumXT recipes

Copy-paste solutions for common tasks. All use the public `sx*` handlers; see the
[API reference](api-reference.md) for every signature and the
[getting-started guide](getting-started.md) for the conventions (bytes are `Data`, failures
throw, etc.). Each snippet is LiveCode Script.

## Encrypt and decrypt a message with a passphrase

A self-contained blob you can store or send: `base64(salt + sealed box)`. The salt is not
secret; it must travel with the ciphertext so the key can be re-derived.

```livecode
function encryptWithPassphrase pPlainText, pPassphrase
   local tSalt, tKey, tSealed
   put sxRandomBytes(16) into tSalt
   put sxPwHash(textEncode(pPassphrase,"utf-8"), tSalt, 32, "2", sxPwMemInteractive()) into tKey
   put sxSecretBox(textEncode(pPlainText,"utf-8"), tKey) into tSealed
   return textDecode(sxBin2Base64(tSalt & tSealed), "ascii")
end encryptWithPassphrase

function decryptWithPassphrase pBlob, pPassphrase
   local tRaw, tSalt, tBox, tKey
   put sxBase642Bin(textEncode(pBlob,"ascii")) into tRaw
   put byte 1 to 16 of tRaw into tSalt
   put byte 17 to -1 of tRaw into tBox
   put sxPwHash(textEncode(pPassphrase,"utf-8"), tSalt, 32, "2", sxPwMemInteractive()) into tKey
   return textDecode(sxSecretBoxOpen(tBox, tKey), "utf-8")   -- throws on wrong passphrase / tamper
end decryptWithPassphrase
```

For higher-value secrets, raise the cost: `sxPwMemModerate()` with `"3"`, or
`sxPwMemSensitive()` with `"4"`. Store the ops/mem you used alongside the data if you might
change it later.

## Encrypt and decrypt a file (any size)

The bytes are streamed chunk-by-chunk in C and never load into a variable, so file size is not
a concern. The output is authenticated: a truncated or altered file fails to decrypt.

```livecode
local tKey
put sxRandomBytes(32) into tKey            -- store/derive this key securely

sxEncryptFile "/path/to/big.mov", "/path/to/big.mov.enc", tKey
sxDecryptFile "/path/to/big.mov.enc", "/path/to/restored.mov", tKey
-- sxDecryptFile throws on a wrong key or a corrupt/truncated file.
```

To key a file from a passphrase, derive `tKey` with `sxPwHash` (as above) and store the salt.

## Store and check a password (login)

Never store a password or a plain hash. `sxPwHashStr` produces a self-describing string that
packs the salt and cost; `sxPwHashStrVerify` checks a candidate in constant time.

```livecode
-- On sign-up: store this string (it is ASCII text).
put textDecode(sxPwHashStr(textEncode(pPassword,"utf-8"), "2", sxPwMemInteractive()), "ascii") into tStored

-- On login:
if sxPwHashStrVerify(tStored, textEncode(pAttempt,"utf-8")) then
   -- access granted
else
   -- rejected
end if
```

## Sign data and verify it

ed25519 signatures: sign with the secret key, verify with the public key. Any change to the
message breaks verification.

```livecode
local tPub, tSec, tSig
sxSignKeypair tPub, tSec                                  -- keep tSec private; publish tPub

put sxSignDetached(textEncode("release v1.0","utf-8"), tSec) into tSig

if sxSignVerifyDetached(tSig, textEncode("release v1.0","utf-8"), tPub) then
   -- authentic and unmodified
end if
```

`sxSignKeypairFromSeed pSeed, tPub, tSec` makes a deterministic keypair from a 32-byte seed if
you need reproducible keys.

## Send a private message to someone (public-key)

Each party has an X25519 keypair and publishes their public key. Encrypt to the recipient's
public key with your own secret key; only they can open it.

```livecode
-- Setup (each party, once):
local tAlicePub, tAliceSec, tBobPub, tBobSec
sxBoxKeypair tAlicePub, tAliceSec
sxBoxKeypair tBobPub, tBobSec

-- Alice -> Bob:
put sxBox(textEncode("hi Bob","utf-8"), tBobPub, tAliceSec) into tBox
-- Bob opens (needs Alice's public key + his own secret key):
put textDecode(sxBoxOpen(tBox, tAlicePub, tBobSec), "utf-8") into tMsg
```

**Anonymous sender?** Use a sealed box - the sender needs only the recipient's public key, and
the recipient cannot tell who sent it:

```livecode
put sxSeal(textEncode("anonymous tip","utf-8"), tBobPub) into tSealed
put textDecode(sxSealOpen(tSealed, tBobPub, tBobSec), "utf-8") into tMsg
```

## Agree on a shared session key (key exchange)

Two parties that each have a key-exchange keypair can derive the same pair of session keys
without sending a secret. `client rx == server tx` and vice versa.

```livecode
local tCPub, tCSec, tSPub, tSSec, tCrx, tCtx, tSrx, tStx
sxKeyExchangeKeypair tCPub, tCSec        -- client
sxKeyExchangeKeypair tSPub, tSSec        -- server

sxKeyExchangeClient tCPub, tCSec, tSPub, tCrx, tCtx
sxKeyExchangeServer tSPub, tSSec, tCPub, tSrx, tStx
-- tCrx == tStx (client receives what server sends); tCtx == tSrx.
-- Use these session keys with sxSecretBox / sxAeadEncrypt.
```

## Hash data or a file (fingerprint / checksum)

```livecode
-- In memory:
put textDecode(sxBin2Hex(sxHash(textEncode("the quick brown fox","utf-8"), 32)), "ascii") into tHex

-- A whole file, streamed C-side:
put textDecode(sxBin2Hex(sxHashFile("/path/to/file", 32)), "ascii") into tFileHex
```

For data you receive in pieces, hash incrementally:

```livecode
local tH
put sxHashInit(32) into tH
sxHashUpdate tH, textEncode("part one ","utf-8")
sxHashUpdate tH, textEncode("part two","utf-8")
put sxHashFinal(tH, 32) into tDigest     -- releases the handle
```

## Authenticated encryption with associated data (AEAD)

Bind a non-secret header (a version, a recipient id) to the ciphertext so it cannot be moved
or replayed elsewhere. Decryption fails if the ciphertext OR the associated data was changed.

```livecode
local tKey, tHeader, tBox
put sxRandomBytes(32) into tKey
put textEncode("v1;to:bob","utf-8") into tHeader
put sxAeadEncrypt(textEncode("{amount:100}","utf-8"), tHeader, tKey) into tBox

put textDecode(sxAeadDecrypt(tBox, tHeader, tKey), "utf-8") into tPlain   -- throws if tHeader differs
```

## A random number you can trust

```livecode
put sxRandomBytes(32) into tKeyBytes          -- 32 secure random bytes
put sxRandomUniform(6) + 1 into tDiceRoll     -- unbiased 1..6
```

Never use the engine `random()` for keys, salts, nonces, or tokens.
