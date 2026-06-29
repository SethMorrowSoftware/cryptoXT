/*
 * sodium_smoke_test.c - the Phase 0 automated suite for the C shim.
 *
 * A crypto binding's worst failure mode is silently mangling bytes (a length
 * off by one, a wrong band on the error code). Round-trip tests alone hide that
 * (mangled-then-unmangled still matches), so this suite leans on KNOWN values
 * and on the NEGATIVE paths that the length/pointer firewall exists to catch.
 *
 * It deliberately exercises the same out-buffer dance the LCB layer performs
 * (allocate small, get -needed, reallocate, fill, copy back) entirely in C,
 * which is the closest we can get to the script -> Pointer -> C -> script trip
 * without the LiveCode engine. The plan's Phase 0 gate is exactly this round
 * trip working byte-for-byte under the sanitizers.
 *
 * Build under gcc ASan + UBSan while iterating (see CLAUDE.md / docs/building.md):
 * a buffer-sizing bug surfaces there, not in a passing round trip.
 */
#include "sodium_shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The pinned libsodium version. This is a known-answer test for the BUILD: it
 * fails loudly if CMake ever links a libsodium other than the one we pinned, so
 * a silent version drift cannot sneak length-constant changes past us. Update
 * this string in the same change that re-pins the version in CMakeLists.txt.
 */
#define SXT_PINNED_SODIUM "1.0.20"

static int g_failures = 0;

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (cond) {                                                         \
            printf("  ok   - %s\n", (msg));                                 \
        } else {                                                            \
            printf("  FAIL - %s   (at %s:%d)\n", (msg), __FILE__, __LINE__);\
            g_failures++;                                                   \
        }                                                                   \
    } while (0)

/* A reusable sentinel so we can prove the shim actually wrote into the buffer
 * (and did not, say, no-op while reporting success). */
static void fill_sentinel(unsigned char *p, int n)
{
    memset(p, 0xAA, (size_t)n);
}

static int all_equal(const unsigned char *p, int n, unsigned char v)
{
    int i;
    for (i = 0; i < n; i++) {
        if (p[i] != v) {
            return 0;
        }
    }
    return 1;
}

static void test_init_and_versions(void)
{
    const char *ver;
    const char *sodver;

    printf("init + versions:\n");

    CHECK(sxt_init() == SXT_OK, "sxt_init() succeeds");
    CHECK(sxt_init() == SXT_OK, "sxt_init() is idempotent");

    CHECK(sxt_abi_version() == SXT_ABI_VERSION, "abi_version matches the header");

    ver = sxt_version();
    CHECK(ver != NULL && ver[0] != '\0', "extension version is a non-empty string");
    CHECK(strcmp(ver, "0.1.0") == 0, "extension version is the expected 0.1.0");

    sodver = sxt_sodium_version();
    CHECK(sodver != NULL, "sodium_version is never NULL");
    /* KAT for the build: the linked libsodium is exactly the pinned version. */
    CHECK(strcmp(sodver, SXT_PINNED_SODIUM) == 0,
          "linked libsodium is the pinned version (" SXT_PINNED_SODIUM ")");

    /* A clean call leaves no error text behind. */
    CHECK(sxt_last_error()[0] == '\0', "last_error is empty after a clean call");
}

static void test_randombytes_firewall(void)
{
    unsigned char buf[32];

    printf("randombytes firewall (negative paths):\n");

    /* Negative count: a hard error in the error band, with a message. */
    CHECK(sxt_randombytes(buf, (int)sizeof(buf), -1) == SXT_ERR_BADARG,
          "negative count -> SXT_ERR_BADARG");
    CHECK(sxt_last_error()[0] != '\0', "an error sets last_error text");

    /* Oversize count: rejected before it could collide with the error band. */
    CHECK(sxt_randombytes(buf, (int)sizeof(buf), SXT_MAX_BUFFER) == SXT_ERR_BADARG,
          "count >= SXT_MAX_BUFFER -> SXT_ERR_BADARG");

    /* cap < n is a SIZE QUERY, not an error: it reports -needed even with a
     * null/zero-capacity buffer, because nothing is written. */
    CHECK(sxt_randombytes(NULL, 0, 16) == -16,
          "size query (cap<n) returns -needed, null buffer allowed");

    /* But once cap is big enough and n > 0, a null destination is a hard error
     * (we are about to write and refuse to write through NULL). */
    CHECK(sxt_randombytes(NULL, 32, 16) == SXT_ERR_BADARG,
          "null buffer with adequate cap and n>0 -> SXT_ERR_BADARG");

    /* Zero bytes is a defined no-op success (yields an empty Data upstream). */
    CHECK(sxt_randombytes(buf, (int)sizeof(buf), 0) == 0, "n==0 writes nothing, returns 0");
    CHECK(sxt_randombytes(NULL, 0, 0) == 0, "n==0 with null/zero buffer returns 0");
}

static void test_randombytes_fills_and_has_entropy(void)
{
    unsigned char a[32];
    unsigned char b[32];

    printf("randombytes fills the buffer with entropy:\n");

    fill_sentinel(a, (int)sizeof(a));
    CHECK(sxt_randombytes(a, (int)sizeof(a), (int)sizeof(a)) == (int)sizeof(a),
          "fill of exactly cap bytes returns the byte count");
    CHECK(!all_equal(a, (int)sizeof(a), 0xAA), "the shim actually overwrote the sentinel");

    CHECK(sxt_randombytes(b, (int)sizeof(b), (int)sizeof(b)) == (int)sizeof(b),
          "second independent draw also succeeds");
    /* Two 32-byte CSPRNG draws colliding is a ~2^-256 event; a match here means
     * the buffer was not actually (re)filled. */
    CHECK(memcmp(a, b, sizeof(a)) != 0, "two draws differ (entropy is flowing)");

    CHECK(sxt_last_error()[0] == '\0', "last_error cleared by the successful call");
}

/*
 * The headline Phase 0 test: drive the exact out-buffer contract the LCB layer
 * implements (allocate a deliberately-too-small block, get -needed, reallocate
 * to the required size, fill, "copy back"). This is the C mirror of the
 * Data round trip the plan insists on proving before anything else.
 */
static void test_out_buffer_retry_round_trip(void)
{
    const int want = 48;
    int cap = 4;                 /* start too small on purpose */
    int rc;
    int retries = 0;
    unsigned char *block;
    unsigned char *copy;

    printf("out-buffer -needed retry round trip:\n");

    block = (unsigned char *)malloc((size_t)cap);
    CHECK(block != NULL, "initial (too-small) allocation");

    for (;;) {
        rc = sxt_randombytes(block, cap, want);
        if (rc >= 0) {
            break;                                  /* fit: rc bytes written */
        }
        if (rc <= SXT_ERR_BASE) {
            CHECK(0, "unexpected hard error during retry");
            free(block);
            return;
        }
        /* rc is in (SXT_ERR_BASE, 0): it is -needed. Grow and retry. */
        cap = -rc;
        retries++;
        block = (unsigned char *)realloc(block, (size_t)cap);
        CHECK(block != NULL, "reallocation to the needed size");
    }

    CHECK(retries == 1, "exactly one retry was needed (-needed then fit)");
    CHECK(rc == want, "final call wrote exactly the requested byte count");
    CHECK(cap == want, "buffer was grown to exactly the needed size");

    /* "Copy back" into an independently owned buffer, the way the LCB layer
     * copies the written bytes into a fresh Data with MCDataCreateWithBytes. */
    copy = (unsigned char *)malloc((size_t)rc);
    CHECK(copy != NULL, "result-copy allocation");
    memcpy(copy, block, (size_t)rc);
    CHECK(memcmp(copy, block, (size_t)rc) == 0, "copied bytes match (round trip intact)");

    free(copy);
    free(block);
}

int main(void)
{
    printf("SodiumXT Phase 0 smoke test\n");
    printf("===========================\n");

    test_init_and_versions();
    test_randombytes_firewall();
    test_randombytes_fills_and_has_entropy();
    test_out_buffer_retry_round_trip();

    printf("---------------------------\n");
    if (g_failures == 0) {
        printf("ALL CHECKS PASSED\n");
        return 0;
    }
    printf("%d CHECK(S) FAILED\n", g_failures);
    return 1;
}
