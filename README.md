# SodiumXT

**SodiumXT** is a [libsodium](https://libsodium.org) binding for OpenXTalk (OXT) / the xTalk
family. It brings modern cryptography (authenticated encryption, Argon2id password hashing, a
streaming AEAD for large files, X25519 boxes, ed25519 signatures, BLAKE2b hashing, a real
CSPRNG) to xTalk, behind a flat C ABI with an LCB layer on top, the same shape as its sibling
extension TorrentXT.

## Status: Phases 0-5 of the C shim are implemented and verified

The full libsodium surface from `docs/SodiumXT-IMPLEMENTATION-PLAN.md` is wrapped in the C
shim and exercised by the test suite:

- **Phase 0** - the FFI buffer round trip (`sxVersion`, `sxRandomBytes`), the proof a `Data`
  survives script -> Pointer -> C -> Pointer -> `Data` intact.
- **Phase 1** - BLAKE2b hashing, hex/base64 encode-decode, constant-time compare.
- **Phase 2** - secretbox + AEAD (prepend random nonce), Argon2id (`pwhash` / `pwhash_str`).
- **Phase 3** - streaming AEAD (secretstream) with a handle table, and C-side
  `sxEncryptFile` / `sxDecryptFile` (the bytes never enter a `Data`; truncation is detected).
- **Phase 4** - X25519 boxes + sealed boxes, ed25519 sign / verify (random or seeded).
- **Phase 5** - key derivation (`kdf`), key exchange (`kx`), and padding.

```
src/sodium_shim.{c,h}   C shim, ABI sxt_* (90 symbols)  ->  sodiumxt.{so,dll,dylib}
src/sodium.lcb          LCB binding, public sx* (47 handlers; static-checked, needs an OXT pass)
tests/sodium_smoke_test.c   125 checks: KATs + round trips + tamper/truncation + the firewall
CMakeLists.txt          acquires a pinned libsodium (1.0.20) and static-links it
tools/                  check-livecodescript.py (static gate) + package-extension.py
```

Verified in this environment: the C shim builds warning-clean (`-Werror`) and all **125**
checks pass under **gcc ASan + UBSan**, with known-answer tests pinned against published /
RFC vectors (BLAKE2b, Argon2id, ed25519) and tamper / wrong-key / truncation tests proving
the authentication actually fails closed. The CMake build produces a `sodiumxt` shared library
exporting **only** the `sxt_*` surface, and the static checker is green.

The **`.lcb` layer is verified statically only** - OXT has no headless compiler here, so its
engine-specific foreign declarations need reconciling against TorrentXT's proven bindings on a
real OXT compile. See the banner at the top of `src/sodium.lcb`.

## What is here

- **`CLAUDE.md`** - the operational guidance and the hard-won-lesson list. Most of the FFI
  and OXT/LCB lessons were paid for while building TorrentXT and are carried over so they are
  not relearned. Read it.
- **`docs/SodiumXT-IMPLEMENTATION-PLAN.md`** - the full spec: the engine decision, the C ABI
  design, the capability surface, the phased plan, the test strategy, and the risk register.
  Read it first.
- **`docs/building.md`** - how to build, test under sanitizers, run the static gate, and
  package the native library.

## Build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSODIUMXT_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure
python3 tools/check-livecodescript.py
```

See `docs/building.md` for the sanitizer build and packaging.

## Why it exists

TorrentXT's optional encryption uses OXT's stock `encrypt ... using "aes-256-cbc" with
password`. That has a weak key derivation (OpenSSL's old `EVP_BytesToKey`) and no
cipher-level authentication. SodiumXT is the proper fix and a reusable building block: any
xTalk app, TorrentXT included, can drop its hand-rolled crypto and call `sx*` instead.

House style: no em-dashes; comment the *why*, densely.
