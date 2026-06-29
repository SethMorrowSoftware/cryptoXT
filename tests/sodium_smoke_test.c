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

    printf("-------------------\n");
    if (g_failures == 0) {
        printf("ALL CHECKS PASSED\n");
        return 0;
    }
    printf("%d CHECK(S) FAILED\n", g_failures);
    return 1;
}
