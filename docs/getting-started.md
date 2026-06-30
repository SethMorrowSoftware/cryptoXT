# Getting started with SodiumXT

This page covers installing SodiumXT and the handful of conventions worth knowing before your
first call. For the full handler list see the [API reference](api-reference.md); for worked
examples see [recipes](recipes.md).

## Install

1. Get SodiumXT (a release download, or a clone of the repository).
2. In the OpenXTalk / LiveCode IDE, install it through the **Extension Manager** like any other
   LiveCode Builder extension.
3. The matching native library is bundled inside the extension under
   `src/code/<arch>-<platform>/`, so the engine resolves it automatically - there is nothing to
   install on the system, and no `LD_LIBRARY_PATH`, `sudo`, or library rename.

Once installed, the library `org.openxtalk.library.sodium` loads and its `sx*` handlers are in
scope in your stacks. Confirm it is working from the message box:

```
put sxVersion()
-- e.g. SodiumXT 0.1.0 (libsodium 1.0.20)
```

## Five conventions

### 1. Bytes are `Data`; text is `String`

Keys, nonces, salts, ciphertext, digests, and signatures are all binary `Data`. When you have
text (a passphrase, a message), convert it on the way in and out:

```livecode
put textEncode("my message", "utf-8") into tBytes    -- text  -> Data
put textDecode(tBytes, "utf-8") into tText            -- Data  -> text
```

Pinning the encoding to `"utf-8"` matters for passphrases: it guarantees the same passphrase
derives the same key on every machine and locale.

### 2. Hex / base64 come back as `Data` too

`sxBin2Hex`, `sxBin2Base64`, and the password-hash string are returned as `Data` (the ASCII
bytes). To display or store one as text, `textDecode(..., "ascii")`:

```livecode
put textDecode(sxBin2Hex(sxHash(textEncode("abc","utf-8"), 32)), "ascii") into tHexString
```

### 3. Functions return a value; some handlers are commands

Most handlers are functions: `put sxHash(d, 32) into x`. A few that have no single return
value are commands - call them as statements, and read their `out` parameters or `the result`:

```livecode
sxEncryptFile tSourcePath, tDestPath, tKey          -- a command

local tPublicKey, tSecretKey
sxBoxKeypair tPublicKey, tSecretKey                 -- out parameters: pass variables
```

### 4. Failures throw - wrap them in `try`

When authentication fails (a wrong key, tampered data, a bad signature), or an argument is
invalid, the handler **throws** rather than returning garbage. That is the point: you find out.
Wrap calls that can fail:

```livecode
try
   put textDecode(sxSecretBoxOpen(tSealed, tKey), "utf-8") into tPlain
catch tError
   answer "Wrong key, or the data was tampered with."
end try
```

Verification handlers (`sxSignVerifyDetached`, `sxPwHashStrVerify`, `sxMemEqual`) are the
exception: an invalid result is a normal `false`, not an error, so you test them with `if`.

### 5. Let SodiumXT manage nonces, and compare secrets safely

You never pass a nonce: the one-shot ciphers draw a fresh random nonce and prepend it, and the
streaming cipher derives per-chunk nonces from a random header. And when you need to compare two
secret values (a MAC, a tag, a token), use `sxMemEqual` (constant time), never `is` or `=`.

## Your first call

```livecode
-- A passphrase-encrypted note, round-tripped.
local tSalt, tKey, tSealed
put sxRandomBytes(16) into tSalt
put sxPwHash(textEncode("hunter2","utf-8"), tSalt, 32, "2", sxPwMemInteractive()) into tKey
put sxSecretBox(textEncode("the eagle lands at noon","utf-8"), tKey) into tSealed

put sxPwHash(textEncode("hunter2","utf-8"), tSalt, 32, "2", sxPwMemInteractive()) into tKey
answer textDecode(sxSecretBoxOpen(tSealed, tKey), "utf-8")    -- the eagle lands at noon
```

Store `tSalt` alongside `tSealed` (for example `sxBin2Base64(tSalt & tSealed)`); you need it to
re-derive the key. The salt is not secret.

## Where next

- [Recipes](recipes.md) - file encryption, password storage, signing, public-key messaging.
- [API reference](api-reference.md) - every handler.
- [Security model](security.md) - the guarantees and the rules.
- [`examples/sodium-demo.livecodescript`](../examples/sodium-demo.livecodescript) - an
  interactive tour you can open and click through.
