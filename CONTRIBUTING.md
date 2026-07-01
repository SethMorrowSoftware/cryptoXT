# Contributing to SodiumXT

Thanks for your interest in improving SodiumXT. Most users never build anything - the extension
ships with prebuilt native libraries for every platform. This page is for people changing the
code.

## Layout

- `src/sodium_shim.{c,h}` - the C shim: a thin marshaling layer over libsodium, exporting the
  stable `sxt_*` ABI.
- `src/sodium.lcb` - the LiveCode Builder binding that presents the public `sx*` handlers.
- `src/code/<arch>-<platform>/` - the bundled native libraries, plus `MANIFEST.sha256` (their
  recorded SHA256s, enforced by the CI `verify-binaries` job); refreshed by CI on `main`.
- `tests/sodium_smoke_test.c` - the C test suite (known-answer tests, round trips, and the
  tamper / wrong-key / firewall checks).
- `tools/` - `check-livecodescript.py` (the static gate for `.lcb` / `.livecodescript`) and
  `package-extension.py`.
- `examples/` - the demo stack and the xTalk self-test.
- `docs/` - user documentation; `docs/development/` - the design and build internals.

## Developer documentation

- **[docs/development/implementation-plan.md](docs/development/implementation-plan.md)** - the
  full spec: the engine decision, the C ABI design, the phased plan, the test strategy, and the
  risk register. Read it first.
- **[docs/development/building.md](docs/development/building.md)** - how to build the native
  library, run the tests under sanitizers, run the static gate, and package the result.
- **[docs/development/torrentxt-integration.md](docs/development/torrentxt-integration.md)** - a
  proposal for replacing TorrentXT's hand-rolled crypto with SodiumXT.
- **`CLAUDE.md`** - the operational guidance and the hard-won-lesson list (FFI, OXT/LCB
  gotchas). Worth reading before touching the binding.

## Build and test (quick version)

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSODIUMXT_BUILD_TESTS=ON
cmake --build build --config Release          # also drops the lib into src/code/<id>/
ctest --test-dir build --output-on-failure    # the C smoke test
python3 tools/check-livecodescript.py          # the static gate for the script layer
```

Always iterate the C shim under the sanitizers (gcc ASan + UBSan) - a buffer-sizing bug in a
crypto binding surfaces there, not in a passing round trip. See
[docs/development/building.md](docs/development/building.md) for the sanitizer build, the
Windows/vcpkg path, and packaging.

## What "done" means

- A `.lcb` / `.livecodescript` change is done once `tools/check-livecodescript.py` passes. There
  is no headless way to run OXT, so claim "verified statically" until it has had an on-engine
  pass.
- A C shim change is done once the smoke test passes under ASan/UBSan, and - for any ABI change -
  `SXT_ABI_VERSION` and the `.lcb` `kSXTABIVersion` are bumped together.
- A native-library change is done once `tools/package-extension.py` has refreshed the committed
  `src/code/<arch>-<platform>/` binary and its `MANIFEST.sha256` entry in the same change.
- CI builds and tests the full platform matrix and refreshes the committed binaries on `main`.

## House style

- Comment the *why*, and match the density of the surrounding code.
- ASCII only in `.lcb` / `.livecodescript` (no smart quotes); no em-dashes in committed prose.
- Develop on a feature branch and open a pull request; do not push to `main` directly.
