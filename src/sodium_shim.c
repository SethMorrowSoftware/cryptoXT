/*
 * sodium_shim.c - implementation of the SodiumXT C ABI.
 *
 * A marshaling layer, not a crypto layer. Each entry validates its lengths and
 * pointers (the length/pointer firewall that replaces TorrentXT's C++ exception
 * firewall, since libsodium is C and does not throw), calls libsodium, and
 * reports a result in the overloaded convention documented in sodium_shim.h.
 *
 * Threading note: libsodium owns no threads, and OXT runs script, the FFI, and
 * rendering on ONE interpreted thread. The init guard and the error buffer are
 * therefore effectively single-threaded. We still keep the error buffer
 * thread-local to honour the plan's "thread-local message" contract and to stay
 * correct if a host ever calls us off-thread.
 */
#include "sodium_shim.h"

#include <sodium.h>
#include <string.h>

#if defined(_MSC_VER)
#  define SXT_THREAD_LOCAL __declspec(thread)
#else
#  define SXT_THREAD_LOCAL _Thread_local
#endif

/*
 * sodium_init() exactly once (CLAUDE.md rule 2): until it has run, the CSPRNG
 * and the runtime CPU-feature detection are not ready. 0 = not yet attempted,
 * 1 = succeeded, -1 = failed. Single-threaded engine, so no lock is needed; the
 * worst a hypothetical race could do is call sodium_init() twice, which is
 * itself defined and safe.
 */
static int s_init_state = 0;

/* Our own storage for the last error: we never hand back a pointer into a
 * transient or library-owned buffer (CLAUDE.md: "never return a library-owned
 * const char* of unknown lifetime"). */
static SXT_THREAD_LOCAL char s_last_error[256];

static void clear_error(void)
{
    s_last_error[0] = '\0';
}

static void set_error(const char *msg)
{
    size_t n;
    if (msg == NULL) {
        s_last_error[0] = '\0';
        return;
    }
    n = strlen(msg);
    if (n >= sizeof(s_last_error)) {
        n = sizeof(s_last_error) - 1;   /* truncate; never overrun our buffer */
    }
    memcpy(s_last_error, msg, n);
    s_last_error[n] = '\0';
}

static int ensure_init(void)
{
    if (s_init_state == 1) {
        return SXT_OK;
    }
    if (s_init_state == -1) {
        set_error("libsodium initialization failed");
        return SXT_ERR_INIT;
    }
    /* sodium_init() returns 0 on first success, 1 if already initialized (both
     * fine), and -1 on failure. Only a negative is an error. */
    if (sodium_init() < 0) {
        s_init_state = -1;
        set_error("libsodium initialization failed");
        return SXT_ERR_INIT;
    }
    s_init_state = 1;
    return SXT_OK;
}

SXT_API int SXT_CALL sxt_init(void)
{
    clear_error();
    return ensure_init();
}

SXT_API const char *SXT_CALL sxt_version(void)
{
    /* Static string literal: program lifetime, so it is safe to return and the
     * engine copies it immediately. */
    return "0.1.0";
}

SXT_API const char *SXT_CALL sxt_sodium_version(void)
{
    /* sodium_version_string() returns a static literal too. Guard on init only
     * so we never return NULL; on failure return "" (never NULL). */
    if (ensure_init() != SXT_OK) {
        return "";
    }
    return sodium_version_string();
}

SXT_API int SXT_CALL sxt_abi_version(void)
{
    return SXT_ABI_VERSION;
}

SXT_API const char *SXT_CALL sxt_last_error(void)
{
    return s_last_error[0] != '\0' ? s_last_error : "";
}

SXT_API int SXT_CALL sxt_randombytes(unsigned char *out, int cap, int n)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }

    /* Validate the length before anything touches memory. A wrong length in C
     * is a memory-corruption bug, not a thrown exception, so it is rejected
     * here, at the boundary (the length/pointer firewall, CLAUDE.md rule 1). */
    if (n < 0) {
        set_error("sxt_randombytes: count must be zero or positive");
        return SXT_ERR_BADARG;
    }
    if (n >= SXT_MAX_BUFFER) {
        /* Larger than a single in-memory Data may carry; would also collide
         * with the hard-error band once negated. Such sizes belong to the
         * file/stream helpers (a future phase), not to one buffer. */
        set_error("sxt_randombytes: count too large for a single buffer");
        return SXT_ERR_BADARG;
    }

    /* The "-needed" half of the out-buffer contract: report the required size
     * WITHOUT writing, so the caller can size its block. Checked before the
     * NULL test on purpose, because a pure size query legitimately passes a
     * null or zero-capacity buffer. */
    if (cap < n) {
        return -n;
    }

    /* From here we are about to write n bytes, so the destination must be real. */
    if (n > 0 && out == NULL) {
        set_error("sxt_randombytes: null output buffer");
        return SXT_ERR_BADARG;
    }

    if (n > 0) {
        randombytes_buf(out, (size_t)n);
    }
    return n;
}
