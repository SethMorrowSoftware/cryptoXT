#!/usr/bin/env python3
"""
package-extension.py - refresh the committed native library for one platform.

The native library ships bundled INSIDE the extension under
    src/code/<arch>-<platform>/sodiumxt.{so,dll,dylib}
with the bare token name (no "lib" prefix). Installing the packaged extension
then lets the engine resolve "c:sodiumxt>" via the revLibraryMapping with no
loose library, no sudo, no LD_LIBRARY_PATH. (See CLAUDE.md and the plan.)

Workflow rule (CLAUDE.md): a native-library change is only "done" once this
script has refreshed the committed binary IN THE SAME CHANGE. CI rebuilds and
tests the full platform matrix; this script handles the one platform you are on.

The platform ids are architecture-FIRST and Windows is "-win32" for BOTH
bitnesses:
    x86_64-linux   x86-linux   x86_64-win32   x86-win32   universal-mac

Usage:
    python3 tools/package-extension.py --build-dir build
    python3 tools/package-extension.py --build-dir build --platform-id x86_64-linux
"""

import argparse
import hashlib
import os
import platform
import shutil
import sys


PLATFORM_SUFFIX = {"linux": ".so", "win32": ".dll", "mac": ".dylib"}

# The provenance manifest that records the SHA256 of every committed native blob
# under src/code/. It lets a consumer (and the CI verify-binaries job) confirm a
# committed binary was not silently swapped or corrupted relative to what the
# packaging step recorded. It does NOT by itself prove a blob matches the source
# it was built from - that guarantee comes from CI rebuilding every platform from
# the pinned libsodium on merge to main - so treat the CI-produced binaries as
# authoritative and this file as their integrity record. Format is plain
# `sha256sum` (hash, two spaces, path relative to src/code), so it verifies with
# `cd src/code && sha256sum -c MANIFEST.sha256`.
MANIFEST_NAME = "MANIFEST.sha256"


def detect_os():
    system = platform.system()
    if system == "Linux":
        return "linux"
    if system == "Windows":
        return "win32"
    if system == "Darwin":
        return "mac"
    raise SystemExit(f"package-extension: unsupported OS '{system}'")


def detect_arch():
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("i386", "i486", "i586", "i686", "x86"):
        return "x86"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    return machine


def default_platform_id():
    os_token = detect_os()
    if os_token == "mac":
        # macOS binaries are shipped as a single universal (lipo'd) binary; a
        # locally built dylib is single-arch, so a true universal build is a CI
        # concern. We still file it under the canonical universal-mac id.
        return "universal-mac"
    return f"{detect_arch()}-{os_token}"


def os_from_platform_id(platform_id):
    if platform_id.endswith("-linux"):
        return "linux"
    if platform_id.endswith("-win32"):
        return "win32"
    if platform_id.endswith("-mac"):
        return "mac"
    raise SystemExit(f"package-extension: cannot infer OS from id '{platform_id}'")


def find_built_library(build_dir, suffix):
    """Locate the freshly built shared library, with or without a lib prefix."""
    candidates = [f"sodiumxt{suffix}", f"libsodiumxt{suffix}"]
    for dirpath, _dirnames, filenames in os.walk(build_dir):
        for wanted in candidates:
            if wanted in filenames:
                return os.path.join(dirpath, wanted)
    raise SystemExit(
        f"package-extension: no sodiumxt{suffix} found under '{build_dir}'. "
        f"Build first: cmake -S . -B {build_dir} && cmake --build {build_dir}")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(repo_root):
    """Rewrite src/code/MANIFEST.sha256 over every committed native blob present.

    Scans src/code/<id>/sodiumxt.{so,dll,dylib}, records each blob's SHA256, and
    writes them sorted for a stable diff. Called after a copy so the manifest
    stays in step with whatever binaries are in the tree; CI's commit-binaries
    job runs the same regeneration after laying down all platforms."""
    code_dir = os.path.join(repo_root, "src", "code")
    entries = []
    for platform_id in sorted(os.listdir(code_dir)):
        blob_dir = os.path.join(code_dir, platform_id)
        if not os.path.isdir(blob_dir):
            continue
        for suffix in PLATFORM_SUFFIX.values():
            blob = os.path.join(blob_dir, f"sodiumxt{suffix}")
            if os.path.isfile(blob):
                rel = os.path.join(platform_id, f"sodiumxt{suffix}")
                entries.append((rel, sha256_of(blob)))
    manifest = os.path.join(code_dir, MANIFEST_NAME)
    with open(manifest, "w", encoding="utf-8", newline="\n") as handle:
        for rel, digest in sorted(entries):
            handle.write(f"{digest}  {rel}\n")
    print(f"package-extension: wrote {manifest} ({len(entries)} blob(s))")
    return manifest


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-dir", default="build",
                        help="CMake build directory holding the built library")
    parser.add_argument("--platform-id", default=None,
                        help="override the detected <arch>-<platform> id")
    parser.add_argument("--repo-root", default=".",
                        help="repository root (where src/code/ lives)")
    parser.add_argument("--manifest-only", action="store_true",
                        help="just regenerate src/code/MANIFEST.sha256 over the "
                             "committed blobs and exit (no build needed); used by "
                             "the commit-binaries CI job after laying down all "
                             "platforms")
    args = parser.parse_args(argv[1:])

    if args.manifest_only:
        write_manifest(args.repo_root)
        return 0

    platform_id = args.platform_id or default_platform_id()
    os_token = os_from_platform_id(platform_id)
    suffix = PLATFORM_SUFFIX[os_token]

    src = find_built_library(args.build_dir, suffix)
    dest_dir = os.path.join(args.repo_root, "src", "code", platform_id)
    dest = os.path.join(dest_dir, f"sodiumxt{suffix}")

    os.makedirs(dest_dir, exist_ok=True)
    shutil.copyfile(src, dest)
    shutil.copymode(src, dest)

    size = os.path.getsize(dest)
    print(f"package-extension: {src} -> {dest} ({size} bytes, id {platform_id})")
    write_manifest(args.repo_root)
    print("Remember to `git add` the refreshed binary AND MANIFEST.sha256 in the "
          "SAME change as the native edit (CLAUDE.md workflow rule).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
