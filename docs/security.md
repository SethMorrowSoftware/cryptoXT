# SodiumXT security model

SodiumXT is a thin binding to [libsodium](https://libsodium.org), an audited, widely used
cryptography library. SodiumXT adds no cryptography of its own: it marshals your data to
libsodium and back, and shapes the API so the easy way is the safe way. This page describes
what that gets you and the few rules you must follow to keep it.

## What you get

- **Authenticated encryption everywhere.** Every cipher carries an authentication tag, so a
  wrong key, a corrupted byte, or deliberate tampering is *detected and rejected* (the call
  throws) rather than decrypting to garbage. This is the main upgrade over the stock
  `encrypt ... using "aes-256-cbc"` path, which is unauthenticated.
- **Strong, memory-hard password hashing.** Passphrases are run through Argon2id, which is
  expensive to brute-force, not a fast hash.
- **Misuse-resistant nonces.** You never supply a nonce. One-shot ciphers generate a fresh
  random nonce and prepend it; the streaming cipher derives per-chunk nonces from a random
  header. Nonce reuse - the classic catastrophic mistake - is designed out of the API.
- **A real CSPRNG.** `sxRandomBytes` and `sxRandomUniform` come from the operating system
  cryptographic random source.

## The primitives

| Purpose | Primitive |
|---|---|
| Secret-key encryption (`sxSecretBox`) | XSalsa20-Poly1305 |
| AEAD (`sxAeadEncrypt`) | XChaCha20-Poly1305-IETF |
| Streaming / file encryption | XChaCha20-Poly1305 (secretstream) |
| Password hashing / key derivation (`sxPwHash`) | Argon2id |
| Public-key encryption (`sxBox`, `sxSeal`) | X25519 + XSalsa20-Poly1305 |
| Signatures (`sxSign*`) | ed25519 |
| Hashing (`sxHash`, `sxHashFile`) | BLAKE2b |
| Key derivation / exchange | BLAKE2b KDF / X25519 (crypto_kx) |

## Rules you must follow

These are the things SodiumXT cannot enforce for you. Following them keeps the guarantees
above intact.

1. **Compare secrets with `sxMemEqual`, never `is` or `=`.** Comparing a MAC, tag, hash, or
   token with the ordinary operators leaks timing information. `sxMemEqual` is constant time.
   (The verify handlers - `sxPwHashStrVerify`, `sxSignVerifyDetached` - already compare safely
   internally.)
2. **Use the CSPRNG for anything unguessable.** Salts, keys, nonces (where you handle them),
   tokens, and session identifiers come from `sxRandomBytes` / `sxRandomUniform`. Never use the
   engine `random()`.
3. **Store the salt, and choose a cost.** A passphrase-derived key needs its salt to be
   re-derived, so store the salt next to the ciphertext (it is not secret). Pick a cost preset
   for the threat: `sxPwMemInteractive()` + `"2"` for logins, `sxPwMemModerate()` + `"3"`, or
   `sxPwMemSensitive()` + `"4"` for high-value data. Record the ops/mem you used so you can
   raise it later without breaking old data.
4. **Pin passphrase encoding to UTF-8.** Always `textEncode(thePassphrase, "utf-8")` before
   hashing, so the same passphrase derives the same key on every machine and locale.
5. **Protect your keys.** SodiumXT cannot manage key lifetime for you (see the limitation
   below). Keep secret keys out of logs, stacks you ship, and version control; derive them when
   needed and discard your references promptly.
6. **Treat a thrown error as a real failure.** If `sxSecretBoxOpen`, `sxBoxOpen`, `sxSignOpen`,
   or `sxDecryptFile` throws, the data was wrong, tampered with, or corrupt. Do not fall back to
   using it - report the failure.

## An honest limitation: key material in memory

libsodium can lock and wipe its own secret buffers, but once a key crosses into a LiveCode
`Data` value it lives in the engine's managed memory. SodiumXT **cannot** reliably lock that
memory against swapping, or guarantee it is zeroed when you are done - the engine may copy or
retain it. Secure-memory guarantees stop at the boundary between libsodium and the script. In
practice this means: minimize how long keys live in script variables, do not write them to disk
or logs, and rely on the operating system's protections. For the highest-value secrets, keep
the sensitive operation (for example whole-file encryption) on the C side via `sxEncryptFile` /
`sxDecryptFile`, where the key is used and dropped without round-tripping through script any
more than necessary.

## What SodiumXT deliberately does not expose

To keep misuse hard, some libsodium features are intentionally omitted:

- **Raw, unauthenticated stream ciphers** (plain XSalsa20 / XChaCha20 / AES-CTR). Everything
  here authenticates.
- **Bring-your-own-nonce variants.** Nonces are managed for you.
- **Raw scalar multiplication / unhashed Diffie-Hellman**, and other low-level primitives that
  are easy to hold wrong.

If you have a concrete need for one of these, that is a discussion for an issue, not something
to work around with hand-rolled crypto next to SodiumXT.

## Provenance and reporting

SodiumXT statically links a pinned release of libsodium, so the cryptography you run is the
upstream audited code, unmodified. On the Linux and macOS builds that release is fetched by exact
version and verified against a pinned SHA256 before it is compiled. The Windows build links the
libsodium that vcpkg provides, which is held to the same libsodium 1.0.x line rather than the
SHA256 pin; every platform must then pass the same known-answer tests (BLAKE2b, Argon2id, ed25519,
KDF) before its binary ships, which is the functional guard against any drift. The committed native
binaries under `src/code/` carry a `MANIFEST.sha256` and are rebuilt from the pinned source and
re-verified by CI; for the strongest assurance you can build from source yourself (see
`docs/development/building.md`).

If you believe you have found a security issue in SodiumXT's binding layer, report it privately to
the maintainer rather than opening a public issue. Vulnerabilities in libsodium itself should go to
the [libsodium project](https://github.com/jedisct1/libsodium).
