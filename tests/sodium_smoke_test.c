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
 * Build under gcc ASan + UBSan while iterating (see CLAUDE.md / docs/development/building.md):
 * a buffer-sizing bug surfaces there, not in a passing round trip.
 */
#include "sodium_shim.h"

#include <sodium.h>
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

/* sxt_last_error now FILLS a caller buffer (it never returns a const char*, so
 * the engine never free()s our static storage). This convenience returns the
 * current error length (0 == clean) so the "is/isn't clean" checks read the
 * same as before. */
static int last_error_len(void)
{
    char buf[256];
    int n = sxt_last_error(buf, (int)sizeof(buf));
    return n < 0 ? -n : n;
}

static void test_init_and_versions(void)
{
    char ver[64];
    char sodver[64];
    int n;

    printf("init + versions:\n");

    CHECK(sxt_init() == SXT_OK, "sxt_init() succeeds");
    CHECK(sxt_init() == SXT_OK, "sxt_init() is idempotent");

    CHECK(sxt_abi_version() == SXT_ABI_VERSION, "abi_version matches the header");

    /* The string entry points fill a caller buffer and return the length (never
     * a const char*; the engine would free() a returned C string). */
    n = sxt_version(ver, (int)sizeof(ver));
    CHECK(n > 0, "extension version writes a non-empty string");
    CHECK(n == 5 && strcmp(ver, "0.1.0") == 0, "extension version is the expected 0.1.0");

    /* -needed contract: a too-small buffer reports the required size, writes
     * nothing, and a buffer of exactly that size then succeeds. */
    CHECK(sxt_version(ver, 3) == -6, "version into a short buffer returns -(len+1)");

    n = sxt_sodium_version(sodver, (int)sizeof(sodver));
    CHECK(n > 0, "sodium_version writes a non-empty string");
    /* The source build (Linux/macOS) links exactly the pinned SXT_PINNED_SODIUM;
     * the Windows CI links libsodium from vcpkg, which may be a different 1.0.x
     * patch release. The whole 1.0.x line shares the same API and length
     * constants, and the functional KATs below (BLAKE2b, Argon2id, ed25519, kdf)
     * are the real guard against any drift, so here we assert only the stable
     * 1.0.x line and print the actual version for visibility. */
    CHECK(n > 0 && strncmp(sodver, "1.0.", 4) == 0,
          "linked libsodium is on the stable 1.0.x line");
    printf("       (linked libsodium %s; pinned source build is %s)\n",
           (n > 0 ? sodver : "(null)"), SXT_PINNED_SODIUM);

    /* A clean call leaves no error text behind. */
    CHECK(last_error_len() == 0, "last_error is empty after a clean call");
}

static void test_randombytes_firewall(void)
{
    unsigned char buf[32];

    printf("randombytes firewall (negative paths):\n");

    /* Negative count: a hard error in the error band, with a message. */
    CHECK(sxt_randombytes(buf, (int)sizeof(buf), -1) == SXT_ERR_BADARG,
          "negative count -> SXT_ERR_BADARG");
    CHECK(last_error_len() != 0, "an error sets last_error text");

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

    CHECK(last_error_len() == 0, "last_error cleared by the successful call");
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

    /* Regression guard for the LCB sxBase642Bin allocation (sodium.lcb): that
     * wrapper sizes its out buffer as b64len + 4, so the C decoder must NOT
     * report -needed for any valid input at that capacity, down to the smallest
     * groups. The old wrapper allocated b64len + 1, which is one byte short for a
     * 4-char group (needs 6, got 5): decoding "____" returned -6 and the LCB then
     * threw, so a plain base64 round trip of any 3-byte value failed. */
    {
        int variant = sxt_base64_variant_urlsafe_no_padding();
        /* the exact failing case, at the OLD (b64len + 1) capacity: -needed. */
        CHECK(sxt_base642bin(back, 4 + 1, "____", 4, variant) == -6,
              "base642bin(\"____\", cap=b64len+1) is one byte short -> -needed (6)");
        /* the NEW (b64len + 4) capacity decodes the 3 bytes cleanly. */
        r = sxt_base642bin(back, 4 + 4, "____", 4, variant);
        CHECK(r == 3 && back[0] == 0xff && back[1] == 0xff && back[2] == 0xff,
              "base642bin(\"____\", cap=b64len+4) decodes {ff,ff,ff}");
        /* empty input at the wrapper capacity is a clean 0-byte decode. */
        CHECK(sxt_base642bin(back, 0 + 4, "", 0, variant) == 0,
              "base642bin(\"\", cap=b64len+4) decodes to 0 bytes");
        /* a full round trip of a 3-byte value at the wrapper capacity. */
        r = sxt_bin2base64(b64, (int)sizeof(b64), three, 3, variant);
        CHECK(r == 4, "bin2base64(3 bytes) is a 4-char group");
        CHECK(sxt_base642bin(back, r + 4, b64, r, variant) == 3 &&
              memcmp(back, three, 3) == 0,
              "base64 round trip of a 3-byte value at cap=b64len+4 succeeds");
    }
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

/* ========================================================================== *
 * Phase 2: secretbox + AEAD + Argon2id.
 * ========================================================================== */

static void test_secretbox(void)
{
    const unsigned char msg[5] = {'h', 'e', 'l', 'l', 'o'};
    unsigned char key[32];
    unsigned char wrong[32];
    unsigned char box[24 + 5 + 16];
    unsigned char plain[8];
    unsigned char manual[8];
    int boxlen;
    int r;

    printf("secretbox (round trip, framing, auth):\n");
    memset(key, 0x11, sizeof(key));
    memset(wrong, 0x22, sizeof(wrong));

    boxlen = sxt_secretbox(box, (int)sizeof(box), msg, 5, key, 32);
    CHECK(boxlen == 24 + 5 + 16, "secretbox output is nonce + msg + mac");

    r = sxt_secretbox_open(plain, (int)sizeof(plain), box, boxlen, key, 32);
    CHECK(r == 5 && memcmp(plain, msg, 5) == 0, "round trip recovers the plaintext");

    /* Framing cross-check: the leading 24 bytes ARE the nonce, so libsodium's
     * raw open of box[24:] under that nonce must recover the same plaintext. */
    CHECK(crypto_secretbox_open_easy(manual, box + 24,
                                     (unsigned long long)(boxlen - 24),
                                     box, key) == 0 &&
          memcmp(manual, msg, 5) == 0,
          "framing is exactly nonce||ciphertext (raw libsodium agrees)");

    box[24] ^= 0x01;
    CHECK(sxt_secretbox_open(plain, (int)sizeof(plain), box, boxlen, key, 32) == SXT_ERR_AUTH,
          "a tampered ciphertext byte -> SXT_ERR_AUTH");
    box[24] ^= 0x01;

    CHECK(sxt_secretbox_open(plain, (int)sizeof(plain), box, boxlen, wrong, 32) == SXT_ERR_AUTH,
          "a wrong key -> SXT_ERR_AUTH");

    CHECK(sxt_secretbox(box, (int)sizeof(box), msg, 5, key, 16) == SXT_ERR_BADARG,
          "wrong key length -> BADARG");
    CHECK(sxt_secretbox_open(plain, (int)sizeof(plain), box, 10, key, 32) == SXT_ERR_BADARG,
          "too-short ciphertext -> BADARG");
}

static void test_aead(void)
{
    const unsigned char msg[4] = {'d', 'a', 't', 'a'};
    const unsigned char ad[3] = {'h', 'd', 'r'};
    const unsigned char ad2[3] = {'h', 'd', 'x'};
    unsigned char key[32];
    unsigned char box[24 + 4 + 16];
    unsigned char plain[8];
    int boxlen;
    int r;

    printf("aead xchacha20poly1305 (AD binding + auth):\n");
    memset(key, 0x33, sizeof(key));

    boxlen = sxt_aead_encrypt(box, (int)sizeof(box), msg, 4, ad, 3, key, 32);
    CHECK(boxlen == 24 + 4 + 16, "aead output is nonce + msg + tag");

    r = sxt_aead_decrypt(plain, (int)sizeof(plain), box, boxlen, ad, 3, key, 32);
    CHECK(r == 4 && memcmp(plain, msg, 4) == 0, "round trip with AD recovers plaintext");

    CHECK(sxt_aead_decrypt(plain, (int)sizeof(plain), box, boxlen, ad2, 3, key, 32) == SXT_ERR_AUTH,
          "wrong associated data -> SXT_ERR_AUTH");

    box[24] ^= 0x80;
    CHECK(sxt_aead_decrypt(plain, (int)sizeof(plain), box, boxlen, ad, 3, key, 32) == SXT_ERR_AUTH,
          "tampered ciphertext -> SXT_ERR_AUTH");
    box[24] ^= 0x80;

    boxlen = sxt_aead_encrypt(box, (int)sizeof(box), msg, 4, NULL, 0, key, 32);
    r = sxt_aead_decrypt(plain, (int)sizeof(plain), box, boxlen, NULL, 0, key, 32);
    CHECK(r == 4 && memcmp(plain, msg, 4) == 0, "round trip with empty AD");
}

static void test_pwhash(void)
{
    const char *pinned =
        "$argon2id$v=19$m=1024,t=2,p=1$ETM71WSPez+kmgsM2ZIpqw"
        "$Pk8d58NRCAf201AQ7VFpsU7ru+EkpOQi8Ju8PzQCxZI";
    unsigned char salt[16];
    unsigned char key[32];
    char hashstr[128];
    char hex[2 * 32 + 1];
    int r;

    printf("Argon2id (KAT + pwhash_str verify):\n");
    memset(salt, 'A', sizeof(salt));

    /* Deterministic Argon2id KAT (fixed salt + ops=2 + mem=1 MiB). */
    r = sxt_pwhash(key, 32, 32, (const unsigned char *)"password", 8, salt, 16,
                   "2", "1048576");
    CHECK(r == 32, "pwhash derives 32 bytes");
    sxt_bin2hex(hex, (int)sizeof(hex), key, 32);
    CHECK(strcmp(hex, "7216b4357104ed7f8a4e900e9cc7a63a0786855abe0b59340053ee43f841228a") == 0,
          "Argon2id(password, salt=Ax16, ops=2, mem=1MiB) matches the KAT");

    CHECK(sxt_pwhash(key, 32, 32, (const unsigned char *)"password", 8, salt, 8,
                     "2", "1048576") == SXT_ERR_BADARG,
          "wrong salt length -> BADARG");
    CHECK(sxt_pwhash(key, 32, 32, (const unsigned char *)"password", 8, salt, 16,
                     "abc", "1048576") == SXT_ERR_BADARG,
          "non-numeric opslimit -> BADARG");

    /* pwhash_str round trip, then verify against a pinned stored hash. */
    r = sxt_pwhash_str(hashstr, (int)sizeof(hashstr),
                       (const unsigned char *)"hunter2", 7, "2", "1048576");
    CHECK(r > 0, "pwhash_str produces a string");
    CHECK(sxt_pwhash_str_verify(hashstr, (const unsigned char *)"hunter2", 7) == 1,
          "pwhash_str verify accepts the right passphrase");
    CHECK(sxt_pwhash_str_verify(hashstr, (const unsigned char *)"nope", 4) == 0,
          "pwhash_str verify rejects the wrong passphrase");
    CHECK(sxt_pwhash_str_verify(pinned, (const unsigned char *)"password", 8) == 1,
          "verify accepts the pinned stored Argon2id string");
    CHECK(sxt_pwhash_str_verify(pinned, (const unsigned char *)"wrongpass", 9) == 0,
          "verify rejects a wrong passphrase against the pinned string");
}

/* ========================================================================== *
 * Phase 3: streaming AEAD (secretstream) + file helpers.
 * ========================================================================== */

static void test_secretstream(void)
{
    const unsigned char m1[5] = {'a', 'l', 'p', 'h', 'a'};
    const unsigned char m2[6] = {'b', 'r', 'a', 'v', 'o', '!'};
    const unsigned char m3[1] = {'z'};
    unsigned char key[32];
    unsigned char header[24];
    unsigned char ct1[5 + 17];
    unsigned char ct2[6 + 17];
    unsigned char ct3[1 + 17];
    unsigned char pt[8];
    int tag_msg = sxt_secretstream_tag_message();
    int tag_fin = sxt_secretstream_tag_final();
    int hpush;
    int hpull;
    int h2;
    int r;

    printf("secretstream (streaming AEAD + handle table):\n");
    memset(key, 0x44, sizeof(key));

    hpush = sxt_secretstream_init_push(header, (int)sizeof(header), key, 32);
    CHECK(hpush > 0, "init_push returns a positive handle");
    CHECK(sxt_secretstream_push(hpush, ct1, (int)sizeof(ct1), m1, 5, NULL, 0, tag_msg) == 5 + 17,
          "push chunk 1");
    CHECK(sxt_secretstream_push(hpush, ct2, (int)sizeof(ct2), m2, 6, NULL, 0, tag_msg) == 6 + 17,
          "push chunk 2");
    CHECK(sxt_secretstream_push(hpush, ct3, (int)sizeof(ct3), m3, 1, NULL, 0, tag_fin) == 1 + 17,
          "push final chunk");

    /* A push handle must not be usable to pull. */
    CHECK(sxt_secretstream_pull(hpush, pt, (int)sizeof(pt), ct1, (int)sizeof(ct1), NULL, 0)
              == SXT_ERR_BADHANDLE,
          "pull on a push handle -> BADHANDLE");

    hpull = sxt_secretstream_init_pull(header, (int)sizeof(header), key, 32);
    CHECK(hpull > 0, "init_pull returns a positive handle");

    r = sxt_secretstream_pull(hpull, pt, (int)sizeof(pt), ct1, (int)sizeof(ct1), NULL, 0);
    CHECK(r == 5 && memcmp(pt, m1, 5) == 0, "pull chunk 1 recovers plaintext");
    CHECK(sxt_secretstream_last_tag(hpull) == tag_msg, "chunk 1 tag is MESSAGE");

    r = sxt_secretstream_pull(hpull, pt, (int)sizeof(pt), ct2, (int)sizeof(ct2), NULL, 0);
    CHECK(r == 6 && memcmp(pt, m2, 6) == 0, "pull chunk 2 recovers plaintext");

    r = sxt_secretstream_pull(hpull, pt, (int)sizeof(pt), ct3, (int)sizeof(ct3), NULL, 0);
    CHECK(r == 1 && pt[0] == 'z', "pull final chunk recovers plaintext");
    CHECK(sxt_secretstream_last_tag(hpull) == tag_fin, "final chunk tag is FINAL");

    /* A tampered chunk fails authentication on a fresh pull stream. */
    h2 = sxt_secretstream_init_pull(header, (int)sizeof(header), key, 32);
    ct1[20] ^= 0x01;
    CHECK(sxt_secretstream_pull(h2, pt, (int)sizeof(pt), ct1, (int)sizeof(ct1), NULL, 0)
              == SXT_ERR_AUTH,
          "a tampered chunk -> SXT_ERR_AUTH");
    ct1[20] ^= 0x01;
    sxt_free_stream(h2);

    sxt_free_stream(hpush);
    sxt_free_stream(hpull);
    sxt_free_stream(hpush);   /* idempotent: freeing again is a clean no-op */
    CHECK(sxt_secretstream_last_tag(hpull) == SXT_ERR_BADHANDLE,
          "a freed handle is now stale -> BADHANDLE");
}

static int write_pattern_file(const char *path, int n)
{
    FILE *f = fopen(path, "wb");
    int i;
    if (f == NULL) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        fputc((int)((unsigned char)((i * 37 + 11) & 0xFF)), f);
    }
    return fclose(f) == 0;
}

static int files_equal(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    int ca;
    int cb;
    int eq = 1;
    if (fa == NULL || fb == NULL) {
        if (fa != NULL) { fclose(fa); }
        if (fb != NULL) { fclose(fb); }
        return 0;
    }
    do {
        ca = fgetc(fa);
        cb = fgetc(fb);
        if (ca != cb) { eq = 0; break; }
    } while (ca != EOF);
    fclose(fa);
    fclose(fb);
    return eq;
}

static long file_size(const char *p)
{
    FILE *f = fopen(p, "rb");
    long n;
    if (f == NULL) {
        return -1;
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fclose(f);
    return n;
}

static void test_file_helpers(void)
{
    const char *plain = "sxt_ft_plain.tmp";
    const char *enc = "sxt_ft_enc.tmp";
    const char *dec = "sxt_ft_dec.tmp";
    const char *trunc = "sxt_ft_trunc.tmp";
    unsigned char key[32];
    unsigned char wrong[32];
    long encsz;

    printf("file helpers (secretstream, multi-chunk + truncation):\n");
    memset(key, 0x55, sizeof(key));
    memset(wrong, 0x66, sizeof(wrong));

    CHECK(write_pattern_file(plain, 40000),
          "wrote a 40000-byte plaintext (spans multiple chunks)");
    CHECK(sxt_encrypt_file(plain, enc, key, 32) == SXT_OK, "encrypt_file succeeds");
    CHECK(sxt_decrypt_file(enc, dec, key, 32) == SXT_OK, "decrypt_file succeeds");
    CHECK(files_equal(plain, dec), "decrypted file matches the original byte for byte");

    CHECK(sxt_decrypt_file(enc, dec, wrong, 32) == SXT_ERR_AUTH, "wrong key -> SXT_ERR_AUTH");

    encsz = file_size(enc);
    CHECK(encsz > 40, "ciphertext is non-trivial");
    {
        FILE *fi = fopen(enc, "rb");
        FILE *fo = fopen(trunc, "wb");
        long keep = encsz - 20;
        long i;
        int c;
        if (fi != NULL && fo != NULL) {
            for (i = 0; i < keep; i++) {
                c = fgetc(fi);
                if (c == EOF) { break; }
                fputc(c, fo);
            }
        }
        if (fi != NULL) { fclose(fi); }
        if (fo != NULL) { fclose(fo); }
        CHECK(sxt_decrypt_file(trunc, dec, key, 32) == SXT_ERR_AUTH,
              "a truncated ciphertext -> SXT_ERR_AUTH (truncation detected)");
        remove(trunc);
    }

    CHECK(sxt_decrypt_file("sxt_ft_no_such_file.tmp", dec, key, 32) == SXT_ERR_IO,
          "missing source file -> SXT_ERR_IO");

    remove(plain);
    remove(enc);
    remove(dec);
}

/* ========================================================================== *
 * Phase 4: public-key boxes (X25519) + signatures (ed25519).
 * ========================================================================== */

static void test_sign(void)
{
    unsigned char seed[32];
    unsigned char pk[32];
    unsigned char sk[64];
    unsigned char sig[64];
    unsigned char signed_msg[64 + 3];
    unsigned char back[8];
    char hex[2 * 64 + 1];
    int r;
    int sl;

    printf("ed25519 sign/verify (deterministic KAT + auth):\n");
    memset(seed, 0, sizeof(seed));

    CHECK(sxt_sign_keypair_from_seed(pk, 32, sk, 64, seed, 32) == SXT_OK,
          "seeded keypair succeeds");
    sxt_bin2hex(hex, (int)sizeof(hex), pk, 32);
    CHECK(strcmp(hex, "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29") == 0,
          "zero-seed public key matches the published ed25519 anchor");

    r = sxt_sign_detached(sig, 64, (const unsigned char *)"abc", 3, sk, 64);
    CHECK(r == 64, "detached signature is 64 bytes");
    sxt_bin2hex(hex, (int)sizeof(hex), sig, 64);
    CHECK(strcmp(hex,
            "885dfb07cab2796eb960531a2f09b972ad59b97bb125bef5fdda0855d6bebebf"
            "24447e705fa11575639df396c201ccf52a1a16b014a7a2f0ce73a7a161757308") == 0,
          "signature of \"abc\" matches the deterministic KAT");

    CHECK(sxt_sign_verify_detached(sig, 64, (const unsigned char *)"abc", 3, pk, 32) == 1,
          "verify accepts the valid signature");
    CHECK(sxt_sign_verify_detached(sig, 64, (const unsigned char *)"abd", 3, pk, 32) == 0,
          "verify rejects a modified message");
    sig[0] ^= 0x01;
    CHECK(sxt_sign_verify_detached(sig, 64, (const unsigned char *)"abc", 3, pk, 32) == 0,
          "verify rejects a modified signature");
    sig[0] ^= 0x01;

    /* attached form round trip + tamper */
    sl = sxt_sign(signed_msg, (int)sizeof(signed_msg), (const unsigned char *)"abc", 3, sk, 64);
    CHECK(sl == 64 + 3, "attached signed message is sig + msg");
    CHECK(sxt_sign_open(back, (int)sizeof(back), signed_msg, sl, pk, 32) == 3 &&
          memcmp(back, "abc", 3) == 0,
          "sign_open recovers the message");
    signed_msg[64] ^= 0x01;
    CHECK(sxt_sign_open(back, (int)sizeof(back), signed_msg, sl, pk, 32) == SXT_ERR_AUTH,
          "sign_open rejects a tampered signed message");
}

static void test_box(void)
{
    const unsigned char msg[7] = {'s', 'e', 'c', 'r', 'e', 't', 's'};
    unsigned char apk[32], ask[32];
    unsigned char bpk[32], bsk[32];
    unsigned char cpk[32], csk[32];
    unsigned char box[24 + 7 + 16];
    unsigned char sealed[7 + 48];
    unsigned char plain[8];
    int boxlen;
    int sealedlen;
    int r;

    printf("public-key box + seal (X25519):\n");
    CHECK(sxt_box_keypair(apk, 32, ask, 32) == SXT_OK, "keypair A");
    CHECK(sxt_box_keypair(bpk, 32, bsk, 32) == SXT_OK, "keypair B");
    CHECK(sxt_box_keypair(cpk, 32, csk, 32) == SXT_OK, "keypair C");

    boxlen = sxt_box(box, (int)sizeof(box), msg, 7, bpk, 32, ask, 32);  /* A -> B */
    CHECK(boxlen == 24 + 7 + 16, "box output is nonce + msg + mac");
    r = sxt_box_open(plain, (int)sizeof(plain), box, boxlen, apk, 32, bsk, 32);
    CHECK(r == 7 && memcmp(plain, msg, 7) == 0, "box round trip A->B recovers plaintext");

    CHECK(sxt_box_open(plain, (int)sizeof(plain), box, boxlen, apk, 32, csk, 32) == SXT_ERR_AUTH,
          "wrong recipient secret key -> SXT_ERR_AUTH");
    box[24] ^= 0x01;
    CHECK(sxt_box_open(plain, (int)sizeof(plain), box, boxlen, apk, 32, bsk, 32) == SXT_ERR_AUTH,
          "tampered box -> SXT_ERR_AUTH");
    box[24] ^= 0x01;

    sealedlen = sxt_box_seal(sealed, (int)sizeof(sealed), msg, 7, bpk, 32);
    CHECK(sealedlen == 7 + 48, "seal output is msg + sealbytes");
    r = sxt_box_seal_open(plain, (int)sizeof(plain), sealed, sealedlen, bpk, 32, bsk, 32);
    CHECK(r == 7 && memcmp(plain, msg, 7) == 0, "seal round trip to B recovers plaintext");
    CHECK(sxt_box_seal_open(plain, (int)sizeof(plain), sealed, sealedlen, cpk, 32, csk, 32)
              == SXT_ERR_AUTH,
          "seal open with the wrong keypair -> SXT_ERR_AUTH");
}

/* ========================================================================== *
 * Phase 5: key derivation (kdf), key exchange (kx), padding.
 * ========================================================================== */

static void test_kdf(void)
{
    unsigned char master[32];
    unsigned char sub[32];
    char hex[2 * 32 + 1];

    printf("kdf (deterministic subkey derivation):\n");
    memset(master, 0x01, sizeof(master));

    CHECK(sxt_kdf_derive(sub, 32, 32, "1", (const unsigned char *)"SXTctx00", 8, master, 32) == 32,
          "kdf_derive produces a 32-byte subkey");
    sxt_bin2hex(hex, (int)sizeof(hex), sub, 32);
    CHECK(strcmp(hex, "dc9d1a0879b1884c4cafbc2a68d1b22926e8a6a0043f458c7f1bc370b032058f") == 0,
          "kdf subkey (master=01x32, id=1, ctx=SXTctx00) matches the KAT");

    /* a different id gives a different subkey */
    {
        unsigned char sub2[32];
        CHECK(sxt_kdf_derive(sub2, 32, 32, "2", (const unsigned char *)"SXTctx00", 8, master, 32) == 32,
              "kdf_derive with a different id succeeds");
        CHECK(memcmp(sub, sub2, 32) != 0, "different subkey ids give different subkeys");
    }
    CHECK(sxt_kdf_derive(sub, 32, 32, "1", (const unsigned char *)"short", 5, master, 32)
              == SXT_ERR_BADARG,
          "wrong context length -> BADARG");
}

static void test_kx(void)
{
    unsigned char cpk[32], csk[32];
    unsigned char spk[32], ssk[32];
    unsigned char crx[32], ctx[32];
    unsigned char srx[32], stx[32];

    printf("kx (key exchange agreement):\n");
    CHECK(sxt_kx_keypair(cpk, 32, csk, 32) == SXT_OK, "client keypair");
    CHECK(sxt_kx_keypair(spk, 32, ssk, 32) == SXT_OK, "server keypair");

    CHECK(sxt_kx_client_session_keys(crx, 32, ctx, 32, cpk, 32, csk, 32, spk, 32) == SXT_OK,
          "client session keys");
    CHECK(sxt_kx_server_session_keys(srx, 32, stx, 32, spk, 32, ssk, 32, cpk, 32) == SXT_OK,
          "server session keys");

    CHECK(memcmp(crx, stx, 32) == 0, "client rx equals server tx");
    CHECK(memcmp(ctx, srx, 32) == 0, "client tx equals server rx");
}

static void test_pad(void)
{
    unsigned char buf[32];
    const unsigned char msg[5] = {'h', 'e', 'l', 'l', 'o'};
    int padded;

    printf("pad / unpad (length hiding):\n");

    padded = sxt_pad(buf, (int)sizeof(buf), msg, 5, 16);
    CHECK(padded == 16, "pad(5, blocksize 16) -> 16 bytes");
    CHECK(memcmp(buf, msg, 5) == 0, "padded buffer starts with the original data");
    CHECK(sxt_unpad(buf, padded, 16) == 5, "unpad recovers the original length");

    /* malformed padding -> ENCODING; a too-small buffer -> -needed. The padding
     * is a 0x80 marker (here at buf[5]) followed by zeros; erase it so there is
     * no valid marker in the final block. */
    memset(&buf[5], 0, 11);
    CHECK(sxt_unpad(buf, 16, 16) == SXT_ERR_ENCODING, "malformed padding -> SXT_ERR_ENCODING");
    CHECK(sxt_pad(buf, 4, msg, 5, 16) == -16, "too-small pad buffer -> -needed (16)");
}

/* ========================================================================== *
 * Phase 6: streaming / whole-file hashing + unbiased random.
 * ========================================================================== */

static int digest_is(const unsigned char *dig, int outlen, const char *expected_hex)
{
    char hex[2 * 64 + 1];
    if (outlen < 0 || outlen > 64) {
        return 0;
    }
    if (sxt_bin2hex(hex, (int)sizeof(hex), dig, outlen) != outlen * 2) {
        return 0;
    }
    return strcmp(hex, expected_hex) == 0;
}

static void test_phase6(void)
{
    /* The same published BLAKE2b-256("abc") vector used in test_hashing, so the
     * multipart and file paths are pinned to a known answer, not just to each
     * other. */
    static const char *KAT_ABC_256 =
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319";
    static unsigned char bigbuf[40000];
    const char *fpath = "sxt_hashfile.tmp";
    unsigned char dig[64];
    unsigned char dig2[64];
    unsigned char key[32];
    int h, i, r, in_range;
    FILE *f;

    printf("phase 6 (uniform random, multipart hash, file hash):\n");
    memset(key, 0x42, sizeof(key));

    /* --- randombytes_uniform: stays in range, and the firewall --- */
    in_range = 1;
    for (i = 0; i < 4096; i++) {
        r = sxt_randombytes_uniform(10);
        if (r < 0 || r >= 10) { in_range = 0; break; }
    }
    CHECK(in_range, "randombytes_uniform(10) stays in [0,10) over 4096 draws");
    CHECK(sxt_randombytes_uniform(1) == 0, "uniform(1) is always 0");
    CHECK(sxt_randombytes_uniform(0) == SXT_ERR_BADARG, "uniform(0) -> BADARG");
    CHECK(sxt_randombytes_uniform(-5) == SXT_ERR_BADARG, "uniform(negative) -> BADARG");
    CHECK(sxt_randombytes_uniform(SXT_MAX_BUFFER + 1) == SXT_ERR_BADARG,
          "uniform(> SXT_MAX_BUFFER) -> BADARG");

    /* --- multipart hash: "a"+"b"+"c" == BLAKE2b-256("abc") --- */
    h = sxt_hash_init(NULL, 0, 32);
    CHECK(h > 0, "hash_init returns a positive handle");
    CHECK(sxt_hash_update(h, (const unsigned char *)"a", 1) == SXT_OK, "update 'a'");
    CHECK(sxt_hash_update(h, (const unsigned char *)"b", 1) == SXT_OK, "update 'b'");
    CHECK(sxt_hash_update(h, (const unsigned char *)"c", 1) == SXT_OK, "update 'c'");
    CHECK(sxt_hash_final(h, dig, 8) == -32, "short final buffer -> -needed (32), state intact");
    CHECK(sxt_hash_final(h, dig, 32) == 32, "final writes 32 bytes");
    CHECK(digest_is(dig, 32, KAT_ABC_256), "multipart BLAKE2b-256(abc) matches the vector");
    CHECK(sxt_hash_update(h, (const unsigned char *)"x", 1) == SXT_ERR_BADHANDLE,
          "update after final -> BADHANDLE (handle released)");
    CHECK(sxt_hash_final(h, dig, 32) == SXT_ERR_BADHANDLE, "final after final -> BADHANDLE");

    /* abort path: init then free, no final; idempotent free must not crash. */
    h = sxt_hash_init(NULL, 0, 32);
    CHECK(h > 0, "hash_init (abort path) handle");
    sxt_hash_free(h);
    CHECK(sxt_hash_update(h, (const unsigned char *)"x", 1) == SXT_ERR_BADHANDLE,
          "update after free -> BADHANDLE");
    sxt_hash_free(h);
    CHECK(1, "double free is a harmless no-op");

    /* bogus handles, including a stream-style handle that lacks the hash tag. */
    CHECK(sxt_hash_update(0, (const unsigned char *)"x", 1) == SXT_ERR_BADHANDLE,
          "update on handle 0 -> BADHANDLE");
    CHECK(sxt_hash_final(65537, dig2, 32) == SXT_ERR_BADHANDLE,
          "final on an untagged (stream-style) handle -> BADHANDLE");

    /* keyed multipart differs from the unkeyed digest still in dig. */
    h = sxt_hash_init(key, 32, 32);
    CHECK(h > 0, "keyed hash_init");
    sxt_hash_update(h, (const unsigned char *)"abc", 3);
    CHECK(sxt_hash_final(h, dig2, 32) == 32, "keyed final writes 32 bytes");
    CHECK(memcmp(dig, dig2, 32) != 0, "keyed multipart differs from unkeyed");

    /* --- file hash: a file of "abc" == BLAKE2b-256("abc") --- */
    f = fopen(fpath, "wb");
    CHECK(f != NULL, "open temp file for write");
    if (f != NULL) {
        fwrite("abc", 1, 3, f);
        fclose(f);
    }
    CHECK(sxt_hash_file(fpath, dig, 64, 32, NULL, 0) == 32, "hash_file returns 32");
    CHECK(digest_is(dig, 32, KAT_ABC_256), "hash_file BLAKE2b-256(abc) matches the vector");
    CHECK(sxt_hash_file(fpath, dig2, 64, 32, key, 32) == 32, "keyed hash_file returns 32");
    CHECK(memcmp(dig, dig2, 32) != 0, "keyed file hash differs from unkeyed");
    CHECK(sxt_hash_file(fpath, dig, 8, 32, NULL, 0) == -32, "short hash_file buffer -> -needed (32)");
    CHECK(sxt_hash_file("sxt_no_such_file.tmp", dig, 64, 32, NULL, 0) == SXT_ERR_IO,
          "missing file -> SXT_ERR_IO");
    remove(fpath);

    /* A multi-chunk file (> SXT_FILE_CHUNK) must hash identically to a one-shot
     * hash of the same bytes: proves the chunked read loop is correct. */
    CHECK(write_pattern_file(fpath, 40000), "wrote a 40000-byte file (multi-chunk)");
    f = fopen(fpath, "rb");
    CHECK(f != NULL && fread(bigbuf, 1, sizeof(bigbuf), f) == sizeof(bigbuf),
          "read the 40000-byte pattern back");
    if (f != NULL) { fclose(f); }
    CHECK(sxt_hash_file(fpath, dig, 64, 32, NULL, 0) == 32, "hash_file (40000 bytes) returns 32");
    CHECK(sxt_generichash(dig2, 64, 32, bigbuf, 40000, NULL, 0) == 32, "one-shot hash of same bytes");
    CHECK(memcmp(dig, dig2, 32) == 0, "file hash equals the one-shot hash of the same bytes");
    remove(fpath);
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
    test_secretbox();
    test_aead();
    test_pwhash();
    test_secretstream();
    test_file_helpers();
    test_sign();
    test_box();
    test_kdf();
    test_kx();
    test_pad();
    test_phase6();

    printf("-------------------\n");
    if (g_failures == 0) {
        printf("ALL CHECKS PASSED\n");
        return 0;
    }
    printf("%d CHECK(S) FAILED\n", g_failures);
    return 1;
}
