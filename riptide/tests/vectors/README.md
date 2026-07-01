# Conformance vectors

`vectors.c` recomputes the deterministic derivations pinned in
[../../12-conformance-vectors.md](../../12-conformance-vectors.md) directly against libsodium and
asserts each matches its published value. It is self-contained (it needs only libsodium, not the
SodiumXT shim), so it runs anywhere libsodium is installed.

```sh
cc -O2 vectors.c -lsodium -o vectors && ./vectors
```

Exit 0 means every vector matched (`ALL VECTORS MATCH`); non-zero means a derivation drifted. KDF
(BLAKE2b), BLAKE2b, and ed25519 outputs are stable across the libsodium 1.0.x line for fixed inputs,
so this passes against any 1.0.x release. The CI runs it on every push.

When Riptide gains an on-engine test harness, add an equivalent check that drives the same
derivations through the `sx*` handlers, so both the C-level and the OXT-level paths are pinned to
these same answers.
