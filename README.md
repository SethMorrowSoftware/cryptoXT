# SodiumXT

**SodiumXT** is a [libsodium](https://libsodium.org) binding for OpenXTalk (OXT) / the xTalk
family. It brings modern cryptography (authenticated encryption, Argon2id password hashing, a
streaming AEAD for large files, X25519 boxes, ed25519 signatures, BLAKE2b hashing, a real
CSPRNG) to xTalk, behind a flat C ABI with an LCB layer on top, the same shape as its sibling
extension TorrentXT.

## Status: Phase 0 (the FFI buffer round-trip)

Phase 0 of `docs/SodiumXT-IMPLEMENTATION-PLAN.md` is in place: the build, the test harness,
the tooling, and exactly two end-to-end entry points (`sxVersion`, `sxRandomBytes`) that prove
a `Data` makes the script -> Pointer -> C -> Pointer -> `Data` trip intact. Everything else
(hashing, secretbox, Argon2id, secretstream, box, sign) is downstream of that and is not built
yet, on purpose.

```
src/sodium_shim.{c,h}   C shim, ABI sxt_*  ->  sodiumxt.{so,dll,dylib}  (one shared lib)
src/sodium.lcb          LCB binding, public sx*  (verified statically; needs an OXT pass)
tests/sodium_smoke_test.c   KATs + the out-buffer round trip + the firewall negative paths
CMakeLists.txt          acquires a pinned libsodium (1.0.20) and static-links it
tools/                  check-livecodescript.py (static gate) + package-extension.py
```

Verified here: the C shim builds warning-clean and the smoke test passes under gcc ASan +
UBSan, the CMake build produces a `sodiumxt` shared library exporting ONLY the `sxt_*` surface,
and the static checker is green. The `.lcb` layer is verified statically only (OXT has no
headless compiler); see `src/sodium.lcb` for what still needs an on-engine pass.

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
