# Building SodiumXT

This documents the heavy part (acquiring and building libsodium) and the day to
day loop (sanitizers, the static gate, packaging). For the design and the phased
plan see `docs/SodiumXT-IMPLEMENTATION-PLAN.md`; for the hard-won lessons see
`CLAUDE.md`.

House style: no em-dashes (hyphens, commas, colons, parentheses instead).

## What gets built

ONE shared library, statically linking a pinned libsodium, named with the bare
token `sodiumxt` (no `lib` prefix):

```
src/sodium_shim.c  +  libsodium (static, pinned)  ->  sodiumxt.{so,dll,dylib}
```

The bare token matters: the packaged extension ships this binary under
`src/code/<arch>-<platform>/sodiumxt.{so,dll,dylib}`, and the engine resolves
`c:sodiumxt>sxt_*` against it via `the revLibraryMapping`. No loose library, no
`sudo`, no `LD_LIBRARY_PATH`, no rename.

## The pinned libsodium

libsodium is pinned in `CMakeLists.txt` and acquired by CMake at build time with
an integrity check:

| | |
|---|---|
| version | `1.0.20` |
| url | `https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz` |
| sha256 | `ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19` |

Re-pinning is a two-file change in one commit: the three `SODIUMXT_LIBSODIUM_*`
values in `CMakeLists.txt` AND the `SXT_PINNED_SODIUM` string in
`tests/sodium_smoke_test.c` (the smoke test asserts the linked version, so a
silent drift fails loudly). libsodium's own build is autotools; on Linux and
macOS CMake drives `./configure --enable-static --disable-shared --with-pic`
through `ExternalProject`, then imports the resulting `libsodium.a`.

> Windows / MSVC: not wired up yet. `CMakeLists.txt` raises a clear
> `FATAL_ERROR` on MSVC rather than guessing a build path. Settling this (the
> bundled `builds/msvc` solution, or vcpkg) is the one remaining Phase 0 CI
> task (plan Risk #6).

## Build and test (Linux, macOS)

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSODIUMXT_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure        # sodium_smoke_test (KATs + round trip)
```

The first build downloads and compiles libsodium (a couple of minutes); later
builds reuse it.

## Always iterate under the sanitizers

A crypto binding is exactly where an off-by-one in buffer sizing hides, so ASan
and UBSan are part of the suite, not an afterthought. Use gcc: clang's ASan
runtime is not installed in the CI environment.

Through CMake:

```sh
cmake -S . -B build-asan -DSODIUMXT_BUILD_TESTS=ON -DSODIUMXT_SANITIZE=ON
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

Or the direct one-liner (libsodium headers treated as system headers with
`-isystem`, so their warnings never pollute our warning-clean `-Wall -Wextra`):

```sh
gcc -std=c11 -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=all \
  -Isrc -isystem <libsodium-include> \
  src/sodium_shim.c tests/sodium_smoke_test.c <path-to>/libsodium.a -o /tmp/sx && /tmp/sx
```

## The static gate for the script layer

OXT is a GUI runtime: there is no headless way to compile or run `.lcb` or
`.livecodescript`. Catch what is statically catchable first:

```sh
python3 tools/check-livecodescript.py
```

It checks smart/curly quotes and dashes, handler / `if` / `repeat` / `unsafe`
balance, constant-declared-before-use, and the prefixed-token-shadow trap. A
green run means "verified statically; still needs an OXT pass" - do not claim
runtime behaviour of the `.lcb` you cannot observe here.

## Packaging the native library

After any native edit, refresh the committed binary for your platform in the
same change:

```sh
python3 tools/package-extension.py --build-dir build
# -> src/code/<arch>-<platform>/sodiumxt.{so,dll,dylib}
git add src/code/<arch>-<platform>/sodiumxt.*
```

Platform ids are architecture-first, and Windows is `-win32` for both bitnesses:
`x86_64-linux`, `x86-linux`, `x86_64-win32`, `x86-win32`, `universal-mac`. CI
builds and tests the full matrix; the script handles the one platform you are
on.

## What "done" means

- A `.lcb` change is done once `tools/check-livecodescript.py` passes.
- A shim change is done once `sodium_smoke_test` passes under ASan/UBSan, and
  (for an ABI change) `SXT_ABI_VERSION` and the `.lcb` `kSXTABIVersion` are
  bumped together.
- A native-library change is done once `tools/package-extension.py` has
  refreshed the committed `src/code/<arch>-<platform>/` binary in the same
  change.
