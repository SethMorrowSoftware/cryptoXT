/*
 * sodium_shim.h - the SodiumXT C ABI (the sxt_* surface).
 *
 * This is the marshaling layer between the LiveCode Builder binding
 * (src/sodium.lcb, public sx*) and libsodium. It adds NO crypto logic of its
 * own: it validates lengths and pointers at the boundary, calls libsodium, and
 * reports bytes-written or a defined error code. See CLAUDE.md ("FFI / C-ABI
 * conventions") and docs/SodiumXT-IMPLEMENTATION-PLAN.md (section 3) for the
 * full rationale; the operative parts are restated here so a reader of the
 * header alone cannot misuse the contract.
 *
 * Phase 0 surface ONLY: init, version, sodium_version, abi_version,
 * last_error, randombytes. Everything else (hashing, secretbox, pwhash,
 * secretstream, box, sign) is downstream of proving the buffer round-trip,
 * which is the plan's Phase 0 gate, so it is intentionally absent here.
 */
#ifndef SODIUMXT_SODIUM_SHIM_H
#define SODIUMXT_SODIUM_SHIM_H

/*
 * Visibility and calling convention. We export ONLY the sxt_* surface, so the
 * shared library is built with hidden default visibility and each public entry
 * is tagged SXT_API. These token names ARE the stable ABI: never rename an
 * exported symbol once shipped, because the .lcb "binds to c:sodiumxt>..."
 * strings reference them by name (a rename is a silent bind failure at load).
 */
#if defined(_WIN32)
#  define SXT_API __declspec(dllexport)
#  define SXT_CALL __cdecl
#else
#  define SXT_API __attribute__((visibility("default")))
#  define SXT_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Bump on ANY ABI change (a new, changed, or removed symbol or signature). The
 * LCB layer compares this against its own literal in checkABI() and throws a
 * clear "reinstall the extension" error on skew, instead of corrupting memory
 * on first use against a mismatched native library.
 */
#define SXT_ABI_VERSION 1

/*
 * The largest single in-memory out-buffer we will service. The return value of
 * a buffer-filling entry point is OVERLOADED (see below), so a "needed" size
 * and a hard-error code must never collide. We cap an in-memory buffer at this
 * value; anything larger MUST go through the (future) file/stream helpers, not
 * a single Data. Kept well under INT_MAX so -SXT_MAX_BUFFER is representable.
 */
#define SXT_MAX_BUFFER 2000000000

/*
 * Error model for the buffer-filling entry points (randombytes, and every
 * cipher that follows). The int return is overloaded into three disjoint bands:
 *
 *   ret >= 0                       bytes written into the caller's buffer.
 *   SXT_ERR_BASE < ret < 0         buffer too small; the required size is -ret
 *                                  ("-needed"). The caller reallocates to -ret
 *                                  and retries. Nothing was written.
 *   ret <= SXT_ERR_BASE            a hard error; sxt_last_error() carries text.
 *
 * The hard-error band sits strictly below any possible "-needed" (because a
 * needed size is in [0, SXT_MAX_BUFFER) and -needed is in (SXT_ERR_BASE, 0]).
 * That disjointness is exactly what keeps the overload unambiguous, so do not
 * widen SXT_MAX_BUFFER without moving SXT_ERR_BASE in lockstep.
 */
#define SXT_ERR_BASE   (-SXT_MAX_BUFFER)
#define SXT_ERR_INIT   (SXT_ERR_BASE - 1)   /* sodium_init() failed             */
#define SXT_ERR_BADARG (SXT_ERR_BASE - 2)   /* null pointer / bad length / args */

/*
 * Status-only entry points (init) use the simpler 0 = ok / negative = error
 * convention; their negatives are the SXT_ERR_* codes above.
 */
#define SXT_OK 0

/* --- Phase 0 surface ------------------------------------------------------ */

/*
 * Run sodium_init() exactly once (idempotent, guarded; CLAUDE.md rule 2).
 * Returns SXT_OK or SXT_ERR_INIT. Every other entry calls this first, so a
 * caller need not invoke it; it exists so script can fail fast with a clear
 * message rather than discover a dead CSPRNG mid-operation.
 */
SXT_API int SXT_CALL sxt_init(void);

/* The SodiumXT extension version (a static string literal; safe to return). */
SXT_API const char *SXT_CALL sxt_version(void);

/* The linked libsodium version (sodium_version_string(), a static literal). */
SXT_API const char *SXT_CALL sxt_sodium_version(void);

/* The ABI version compiled into this library (== SXT_ABI_VERSION). */
SXT_API int SXT_CALL sxt_abi_version(void);

/*
 * The last error message on this thread, or "" when clean. NEVER returns NULL
 * (handing NULL back where script expects a string is its own crash). The
 * pointer is into thread-local storage with process lifetime; the engine
 * copies it immediately.
 */
SXT_API const char *SXT_CALL sxt_last_error(void);

/*
 * Fill out[0..n) with n cryptographically secure random bytes (randombytes_buf,
 * the ONLY sanctioned source of salts, nonces, and keys).
 *
 * This is the canonical out-buffer round-trip and the template every later
 * cipher follows:
 *   - n < 0                         -> SXT_ERR_BADARG.
 *   - n >= SXT_MAX_BUFFER           -> SXT_ERR_BADARG (too large for one Data).
 *   - cap < n                       -> return -n (required size; nothing written).
 *   - cap >= n, n > 0, out == NULL  -> SXT_ERR_BADARG.
 *   - otherwise                     -> write n bytes, return n.
 * out and cap describe the caller's block (an MCMemoryAllocate block on the LCB
 * side). The shim never reads or writes past cap (the length/pointer firewall,
 * CLAUDE.md rule 1).
 */
SXT_API int SXT_CALL sxt_randombytes(unsigned char *out, int cap, int n);

#ifdef __cplusplus
}
#endif
#endif /* SODIUMXT_SODIUM_SHIM_H */
