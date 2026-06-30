# SodiumXT

**Modern, authenticated cryptography for OpenXTalk and the xTalk family, made easy.**

SodiumXT is a [libsodium](https://libsodium.org) binding for OpenXTalk (OXT) / LiveCode. It
gives xTalk apps the cryptography people actually need today, behind a small, friendly set of
`sx*` handlers:

- **Authenticated encryption** with a passphrase or a key (secretbox, AEAD) - tampering and
  wrong keys are *rejected*, never silently mis-decrypted.
- **Password hashing** with Argon2id (memory-hard), for login checks and key derivation.
- **Large files**: encrypt, decrypt, and hash files of any size, streamed so they never have
  to fit in memory.
- **Public-key** encryption and **sealed boxes** (X25519), and **digital signatures**
  (ed25519).
- **Hashing** (BLAKE2b), **hex/base64**, **key exchange**, and a real **cryptographic random**
  generator.

It wraps the audited libsodium library, so you can delete hand-rolled crypto and just call
`sx*` instead.

## Why

The stock `encrypt ... using "aes-256-cbc" with password ...` path in xTalk has a weak key
derivation and no integrity checking: a corrupted or tampered ciphertext decrypts to garbage
instead of failing. SodiumXT fixes both. Argon2id makes passphrases expensive to guess, and
every cipher carries an authentication tag, so a wrong key or a single flipped byte is
detected and rejected.

## Requirements

- OpenXTalk, or LiveCode 9.6.3+ (anything that loads LiveCode Builder extensions).
- Desktop platforms: **Linux** (x86_64, x86), **macOS** (universal), **Windows** (64- and
  32-bit). The matching native library ships bundled inside the extension; there is nothing to
  install separately, and no `LD_LIBRARY_PATH` or `sudo` needed.

## Install

1. Get SodiumXT (download a release, or clone this repository).
2. In the OpenXTalk / LiveCode IDE, install it through the **Extension Manager**, the same way
   you install any LCB extension. The per-platform native library under `src/code/` is
   resolved automatically by the engine.
3. Verify it loaded from the message box:

   ```
   put sxVersion()
   -- e.g. SodiumXT 0.1.0 (libsodium 1.0.20)
   ```

Once installed, the `sx*` handlers are in scope in your stacks. See
[docs/getting-started.md](docs/getting-started.md) for the few conventions worth knowing
before your first call.

## Quick start: encrypt a message with a passphrase

```livecode
local tSalt, tKey, tSealed, tPlain

-- Encrypt. Keep tSalt next to the ciphertext so you can re-derive the key later.
put sxRandomBytes(16) into tSalt
put sxPwHash(textEncode("my passphrase", "utf-8"), tSalt, 32, "2", sxPwMemInteractive()) into tKey
put sxSecretBox(textEncode("Attack at dawn.", "utf-8"), tKey) into tSealed

-- Decrypt. Re-derive the same key from the stored salt, then open.
put sxPwHash(textEncode("my passphrase", "utf-8"), tSalt, 32, "2", sxPwMemInteractive()) into tKey
put textDecode(sxSecretBoxOpen(tSealed, tKey), "utf-8") into tPlain   -- "Attack at dawn."
```

If the passphrase is wrong or the ciphertext was tampered with, `sxSecretBoxOpen` throws
instead of returning garbage - wrap it in `try ... catch`.

## Documentation

- **[Getting started](docs/getting-started.md)** - install, load, the `Data` / `textEncode`
  rules, and how errors are reported.
- **[API reference](docs/api-reference.md)** - every `sx*` handler by category.
- **[Recipes](docs/recipes.md)** - copy-paste solutions for common tasks (file encryption,
  password storage, signing, public-key messaging, key exchange).
- **[Security model](docs/security.md)** - what SodiumXT guarantees, and the handful of rules
  to follow so you keep those guarantees.

## Examples

Two ready-to-run stacks are in [`examples/`](examples):

- **`sodium-demo.livecodescript`** - an interactive, tabbed showcase: passphrase encryption
  (with a live tamper-rejection demo), public-key messaging, signatures, hashing, and file
  encryption, each with step-by-step guidance.
- **`sodium-tests.livecodescript`** - a self-test: `put sxSelfTest()` runs every capability
  through round-trips, known-answer vectors, and tamper / wrong-key checks and returns a
  pass/fail report.

## Security at a glance

SodiumXT is designed so the easy way is the safe way:

- Nonces are handled for you (a fresh random nonce is generated and prepended, or derived
  per chunk). There is no error-prone "bring your own nonce" entry point.
- Compare secrets with `sxMemEqual` (constant time), never with `is` or `=`.
- Use `sxRandomBytes` / `sxRandomUniform` for anything that must be unguessable, never the
  engine `random()`.
- Store the salt (and the cost settings) alongside a passphrase-derived ciphertext so you can
  re-derive and raise the cost later.

The full model and the reasoning are in [docs/security.md](docs/security.md).

## Contributing / building from source

Most users never need to build anything - the extension ships with prebuilt native libraries
for every platform. If you want to build from source, change the C shim, or contribute, see
[CONTRIBUTING.md](CONTRIBUTING.md) and [`docs/development/`](docs/development).

## License

SodiumXT is released under the [MIT License](LICENSE). It statically links libsodium, which is
distributed under the ISC license. See `LICENSE` for details.
