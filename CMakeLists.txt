# CMakeLists.txt - build the SodiumXT native shim.
#
# What this produces: ONE shared library, statically linking a PINNED libsodium,
# named with the bare token "sodiumxt" (no "lib" prefix), so the packaged
# extension can resolve "c:sodiumxt>" with no external runtime dependency. See
# docs/SodiumXT-IMPLEMENTATION-PLAN.md sections 3 and 7, and CLAUDE.md.
#
# libsodium's own build is autotools. On Linux and macOS we drive that via
# ExternalProject (the known-good path), then import the resulting static lib.
# The Windows/MSVC build path is the one remaining Phase 0 CI item (plan Risk
# #6); it errors loudly below rather than guessing, so a Windows build fails
# informatively instead of silently linking the wrong thing.

cmake_minimum_required(VERSION 3.16)

project(SodiumXT
        VERSION 0.1.0
        DESCRIPTION "Modern cryptography for OpenXTalk / xTalk via libsodium"
        LANGUAGES C)

# ---------------------------------------------------------------------------
# Pinned libsodium.
#
# Re-pinning is a two-file change: bump these three values AND the
# SXT_PINNED_SODIUM known-answer string in tests/sodium_smoke_test.c, in the
# same commit. The sha256 is the integrity gate on the download.
# ---------------------------------------------------------------------------
set(SODIUMXT_LIBSODIUM_VERSION "1.0.20"
    CACHE STRING "Pinned libsodium release to build and static-link")
set(SODIUMXT_LIBSODIUM_URL
    "https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz"
    CACHE STRING "Download URL for the pinned libsodium source tarball")
set(SODIUMXT_LIBSODIUM_SHA256
    "ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19"
    CACHE STRING "Expected sha256 of the pinned libsodium tarball")

option(SODIUMXT_BUILD_TESTS "Build the C smoke test (ctest)" OFF)
option(SODIUMXT_SANITIZE    "Build the smoke test under gcc ASan + UBSan" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Acquire and build libsodium (static, PIC, no shared), then import it.
# ---------------------------------------------------------------------------
include(ExternalProject)

set(_sodium_prefix  "${CMAKE_BINARY_DIR}/libsodium")
set(_sodium_install "${_sodium_prefix}/install")
set(_sodium_include "${_sodium_install}/include")
set(_sodium_lib
    "${_sodium_install}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}sodium${CMAKE_STATIC_LIBRARY_SUFFIX}")

if(MSVC)
    # libsodium ships an MSVC solution under builds/msvc; wiring that (or vcpkg)
    # into this import is the remaining Phase 0 task. Fail clearly rather than
    # produce a half-built library.
    message(FATAL_ERROR
        "SodiumXT: the MSVC libsodium build path is not wired up yet (plan Risk #6). "
        "Build on Linux/macOS for now, or supply a prebuilt static libsodium and "
        "set _sodium_lib / _sodium_include by hand.")
else()
    ExternalProject_Add(libsodium_ext
        URL              "${SODIUMXT_LIBSODIUM_URL}"
        URL_HASH         "SHA256=${SODIUMXT_LIBSODIUM_SHA256}"
        PREFIX           "${_sodium_prefix}"
        # --with-pic: the static objects get linked into our SHARED library, so
        # they must be position independent. static-only keeps it self-contained.
        CONFIGURE_COMMAND <SOURCE_DIR>/configure
                          --prefix=<INSTALL_DIR>
                          --enable-static --disable-shared
                          --with-pic
                          --disable-dependency-tracking
        BUILD_COMMAND     ${CMAKE_MAKE_PROGRAM} -j
        INSTALL_COMMAND   ${CMAKE_MAKE_PROGRAM} install
        INSTALL_DIR       "${_sodium_install}"
        BUILD_BYPRODUCTS  "${_sodium_lib}"
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
endif()

# Import the not-yet-built static lib. The include dir must exist at configure
# time for the INTERFACE include to be valid, so create it up front.
file(MAKE_DIRECTORY "${_sodium_include}")

add_library(sodiumxt::libsodium STATIC IMPORTED GLOBAL)
set_target_properties(sodiumxt::libsodium PROPERTIES
    IMPORTED_LOCATION "${_sodium_lib}")
# SYSTEM so libsodium's own headers never pollute our -Wall -Wextra. Our code
# stays warning-clean; theirs is treated as a system header.
target_include_directories(sodiumxt::libsodium SYSTEM INTERFACE "${_sodium_include}")

# ---------------------------------------------------------------------------
# Warning flags applied to OUR code only (libsodium headers are SYSTEM above).
# ---------------------------------------------------------------------------
function(sodiumxt_apply_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W3)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra)
    endif()
endfunction()

# ---------------------------------------------------------------------------
# The shim: ONE shared library, bare token "sodiumxt", hidden visibility so
# only the SXT_API-tagged sxt_* symbols are exported.
# ---------------------------------------------------------------------------
add_library(sodiumxt SHARED src/sodium_shim.c)
add_dependencies(sodiumxt libsodium_ext)
set_target_properties(sodiumxt PROPERTIES
    PREFIX ""                 # no "lib" prefix: the engine resolves the bare token
    OUTPUT_NAME "sodiumxt"
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON)
target_include_directories(sodiumxt PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(sodiumxt PRIVATE sodiumxt::libsodium)
sodiumxt_apply_warnings(sodiumxt)

# Export ONLY the sxt_* ABI. Hidden visibility (above) governs our own code, but
# symbols pulled from the static libsodium archive would otherwise be re-exported
# from the shared library. A stray exported sodium_init/randombytes_buf is untidy
# and can collide with another library the host has loaded, so we strip them.
if(APPLE)
    target_link_options(sodiumxt PRIVATE
        "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/cmake/sodiumxt.exp")
elseif(NOT MSVC)
    # GNU ld / lld: do not re-export symbols brought in from static archives.
    target_link_options(sodiumxt PRIVATE "-Wl,--exclude-libs,ALL")
endif()

# ---------------------------------------------------------------------------
# Smoke test (KATs + the out-buffer round trip + the firewall negative paths).
# The test links the shim SOURCE directly (not the .so), so it exercises the
# same objects under the sanitizers.
# ---------------------------------------------------------------------------
if(SODIUMXT_BUILD_TESTS)
    enable_testing()
    add_executable(sodium_smoke_test tests/sodium_smoke_test.c src/sodium_shim.c)
    add_dependencies(sodium_smoke_test libsodium_ext)
    set_target_properties(sodium_smoke_test PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON)
    target_include_directories(sodium_smoke_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(sodium_smoke_test PRIVATE sodiumxt::libsodium)
    sodiumxt_apply_warnings(sodium_smoke_test)

    if(SODIUMXT_SANITIZE AND NOT MSVC)
        # A crypto binding is exactly where an off-by-one in buffer sizing hides,
        # so the sanitizers are part of the suite, not an afterthought.
        target_compile_options(sodium_smoke_test PRIVATE
            -fsanitize=address,undefined -fno-sanitize-recover=all)
        target_link_options(sodium_smoke_test PRIVATE
            -fsanitize=address,undefined -fno-sanitize-recover=all)
    endif()

    add_test(NAME sodium_smoke_test COMMAND sodium_smoke_test)
endif()
