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

/* ========================================================================== *
 * Phase 1: hashing + encoding + constant-time compare.
 * ========================================================================== */

static int hash_hex_equals(const char *msg, int msglen, int outlen,
                           const char *expected_hex)
{
    unsigned char dig[64];
    char hex[2 * 64 + 1];
    if (sxt_generichash(dig, (int)sizeof(dig), outlen,
                        (const unsigned char *)msg, msglen, NULL, 0) != outlen) {
        return 0;
    }
    if (sxt_bin2hex(hex, (int)sizeof(hex), dig, outlen) != outlen * 2) {
        return 0;
    }
    return strcmp(hex, expected_hex) == 0;
}

static void test_hashing(void)
{
    unsigned char dig[64];
    char small[8];
    unsigned char k[32];
    unsigned char a[32];
    unsigned char b[32];

    printf("hashing (BLAKE2b KATs + firewall):\n");

    /* Independent published / RFC 7693 known-answer vectors. */
    CHECK(hash_hex_equals("", 0, 32,
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"),
          "BLAKE2b-256(\"\") matches the published vector");
    CHECK(hash_hex_equals("abc", 3, 32,
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
          "BLAKE2b-256(\"abc\") matches the published vector");
    CHECK(hash_hex_equals("abc", 3, 64,
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
          "BLAKE2b-512(\"abc\") matches the RFC 7693 vector");

    /* A keyed hash must differ from the unkeyed hash of the same message. */
    memset(k, 0x42, sizeof(k));
    CHECK(sxt_generichash(a, 32, 32, (const unsigned char *)"abc", 3, k, 32) == 32,
          "keyed hash succeeds");
    CHECK(sxt_generichash(b, 32, 32, (const unsigned char *)"abc", 3, NULL, 0) == 32,
          "unkeyed hash succeeds");
    CHECK(memcmp(a, b, 32) != 0, "keyed and unkeyed digests differ");

    /* Firewall: out-of-range digest length, then the -needed path. */
    CHECK(sxt_generichash(dig, 64, 8, (const unsigned char *)"x", 1, NULL, 0) == SXT_ERR_BADARG,
          "digest length below min -> BADARG");
    CHECK(sxt_generichash(dig, 64, 100, (const unsigned char *)"x", 1, NULL, 0) == SXT_ERR_BADARG,
          "digest length above max -> BADARG");
    CHECK(sxt_generichash((unsigned char *)small, 8, 32,
                          (const unsigned char *)"x", 1, NULL, 0) == -32,
          "too-small digest buffer -> -needed (32)");
}

static void test_encoding(void)
{
    unsigned char bin[4] = {0xde, 0xad, 0xbe, 0xef};
    unsigned char three[3] = {0xff, 0xff, 0xff};
    unsigned char hello[5] = {'H', 'e', 'l', 'l', 'o'};
    unsigned char back[16];
    char hex[16];
    char b64[16];
    int r;

    printf("encoding (hex / base64 round trips + KATs):\n");

    r = sxt_bin2hex(hex, (int)sizeof(hex), bin, 4);
    CHECK(r == 8 && strcmp(hex, "deadbeef") == 0, "bin2hex({de,ad,be,ef}) == \"deadbeef\"");

    r = sxt_hex2bin(back, (int)sizeof(back), "deadbeef", 8);
    CHECK(r == 4 && memcmp(back, bin, 4) == 0, "hex2bin round trip");

    CHECK(sxt_hex2bin(back, (int)sizeof(back), "deadbeeg", 8) == SXT_ERR_ENCODING,
          "malformed hex -> SXT_ERR_ENCODING");

    r = sxt_bin2base64(b64, (int)sizeof(b64), three, 3,
                       sxt_base64_variant_urlsafe_no_padding());
    CHECK(r == 4 && strcmp(b64, "____") == 0,
          "bin2base64 urlsafe-no-pad({ff,ff,ff}) == \"____\"");

    r = sxt_bin2base64(b64, (int)sizeof(b64), hello, 5, sxt_base64_variant_original());
    CHECK(r == 8 && strcmp(b64, "SGVsbG8=") == 0,
          "bin2base64 original(\"Hello\") == \"SGVsbG8=\"");
    r = sxt_base642bin(back, (int)sizeof(back), "SGVsbG8=", 8, sxt_base64_variant_original());
    CHECK(r == 5 && memcmp(back, hello, 5) == 0, "base642bin round trip");

    /* 4 bytes need 9 (8 hex chars + NUL); a 2-byte buffer reports -needed. */
    CHECK(sxt_bin2hex(hex, 2, bin, 4) == -9, "bin2hex short buffer -> -needed (9)");
}

static void test_memequal(void)
{
    unsigned char a[4] = {1, 2, 3, 4};
    unsigned char b[4] = {1, 2, 3, 4};
    unsigned char c[4] = {1, 2, 3, 5};
    unsigned char d[3] = {1, 2, 3};

    printf("constant-time compare:\n");
    CHECK(sxt_memequal(a, 4, b, 4) == 1, "equal buffers -> 1");
    CHECK(sxt_memequal(a, 4, c, 4) == 0, "differing buffers -> 0");
    CHECK(sxt_memequal(a, 4, d, 3) == 0, "different lengths -> 0");
    CHECK(sxt_memequal(NULL, 0, NULL, 0) == 1, "two empty buffers -> 1");
}

int main(void)
{
    printf("SodiumXT smoke test\n");
    printf("===================\n");

    test_init_and_versions();
    test_randombytes_firewall();
    test_randombytes_fills_and_has_entropy();
    test_out_buffer_retry_round_trip();
    test_hashing();
    test_encoding();
    test_memequal();

    printf("-------------------\n");
    if (g_failures == 0) {
        printf("ALL CHECKS PASSED\n");
        return 0;
    }
    printf("%d CHECK(S) FAILED\n", g_failures);
    return 1;
}
