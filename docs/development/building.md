# Building SodiumXT

This documents the heavy part (acquiring and building libsodium) and the day to
day loop (sanitizers, the static gate, packaging). For the design and the phased
plan see `docs/development/implementation-plan.md`; for the hard-won lessons see
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

> Windows / MSVC links libsodium from **vcpkg** instead of building the pinned
> source: install `libsodium:<triplet>-static` and pass the vcpkg toolchain (see
> "Build and test (Windows)" below). The CI matrix builds all five platforms.

## Where the built library lands

A plain `cmake --build` now copies the freshly built library into the bundle
location the packaged extension reads:

```
src/code/<arch>-<platform>/sodiumxt.{so,dll,dylib}
```

so the engine can resolve `c:sodiumxt>` with no extra step. The platform id is
detected automatically (architecture-first; Windows is `-win32` for both
bitnesses; macOS files under `universal-mac`); override it for a cross build with
`-DSODIUMXT_PLATFORM_ID=<id>`, or turn the copy off with
`-DSODIUMXT_PLACE_IN_SRC=OFF`.

## Build and test (Linux, macOS)

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSODIUMXT_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure        # sodium_smoke_test (KATs + round trip)
# -> build also wrote src/code/<arch>-<platform>/sodiumxt.{so,dylib}
```

The first build downloads and compiles libsodium (a couple of minutes); later
builds reuse it.

## Build and test (Windows / MSVC)

Windows links libsodium from vcpkg. From a Developer PowerShell (so `cl.exe` is
on PATH), with `VCPKG_INSTALLATION_ROOT` set to your vcpkg checkout:

```powershell
vcpkg install libsodium:x64-windows-static          # or x86-windows-static for 32-bit

cmake -S . -B build -G "NMake Makefiles" `
  -DCMAKE_BUILD_TYPE=Release `
  -DSODIUMXT_BUILD_TESTS=ON `
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build
ctest --test-dir build --output-on-failure
# -> build also wrote src\code\x86_64-win32\sodiumxt.dll
```

The `NMake Makefiles` generator avoids the Visual Studio generator's VS-instance
detection (which can fail on minimal runners) and gives a native `cl.exe` for the
architecture of the Developer shell you launched. Use the `x86-windows-static`
triplet from a 32-bit Developer shell to produce the `x86-win32` `.dll`.

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

`cmake --build` already copies the library into
`src/code/<arch>-<platform>/sodiumxt.{so,dll,dylib}` (see "Where the built
library lands"), so after a build it is in place. To track it in the repo for
your platform, in the same change as the native edit:

```sh
git add src/code/<arch>-<platform>/sodiumxt.*
```

If you have a build tree you do not want to reconfigure (or want to copy from a
build dir that did not run the post-build step, e.g. one built with
`-DSODIUMXT_PLACE_IN_SRC=OFF`), do the same copy explicitly:

```sh
python3 tools/package-extension.py --build-dir build
# -> src/code/<arch>-<platform>/sodiumxt.{so,dll,dylib}
```

Platform ids are architecture-first, and Windows is `-win32` for both bitnesses:
`x86_64-linux`, `x86-linux`, `x86_64-win32`, `x86-win32`, `universal-mac`. CI
builds and tests the full matrix; the build (and the script) handle the one
platform you are on.

`package-extension.py` also refreshes `src/code/MANIFEST.sha256`, a plain
`sha256sum` list of every committed native blob. The CI `verify-binaries` job
recomputes those hashes on every push and pull request and fails if a committed
`sodiumxt.*` is unlisted or does not match, so a binary cannot be swapped or
corrupted without the manifest being updated in the same change. Verify locally
with `cd src/code && sha256sum -c MANIFEST.sha256`. The manifest is an integrity
record, not a source-provenance proof: the binaries that ship are the ones CI
rebuilds from the pinned libsodium (the `commit-binaries` job on `main`
regenerates both the blobs and the manifest), so treat those as authoritative and
build from source when you need end-to-end assurance.

## A note on the pinned libsodium

The Linux and macOS builds fetch libsodium by exact version and check it against
the `SODIUMXT_LIBSODIUM_SHA256` pin in `CMakeLists.txt` before building. The
Windows build links the libsodium supplied by vcpkg, which follows the same
libsodium 1.0.x line but is not covered by that SHA256 pin; the known-answer
tests (BLAKE2b, Argon2id, ed25519, KDF) run on every platform and are the guard
against a constant or behaviour drift there. If you need the Windows binary held
to an exact libsodium, pin the vcpkg baseline (a `vcpkg.json` manifest with a
`builtin-baseline`) or build the pinned source on Windows too.

## What "done" means

- A `.lcb` change is done once `tools/check-livecodescript.py` passes.
- A shim change is done once `sodium_smoke_test` passes under ASan/UBSan, and
  (for an ABI change) `SXT_ABI_VERSION` and the `.lcb` `kSXTABIVersion` are
  bumped together.
- A native-library change is done once `tools/package-extension.py` has
  refreshed the committed `src/code/<arch>-<platform>/` binary AND the
  `src/code/MANIFEST.sha256` entry in the same change (the script does both;
  `verify-binaries` in CI enforces the manifest).
