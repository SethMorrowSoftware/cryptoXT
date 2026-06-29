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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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

/* ========================================================================== *
 * Phase 1: hashing + encoding + constant-time compare.
 * ========================================================================== */

/* Length constants as functions: the LCB layer must never hardcode these. */
SXT_API int SXT_CALL sxt_hash_bytes(void)        { return (int)crypto_generichash_BYTES; }
SXT_API int SXT_CALL sxt_hash_bytes_min(void)    { return (int)crypto_generichash_BYTES_MIN; }
SXT_API int SXT_CALL sxt_hash_bytes_max(void)    { return (int)crypto_generichash_BYTES_MAX; }
SXT_API int SXT_CALL sxt_hash_keybytes(void)     { return (int)crypto_generichash_KEYBYTES; }
SXT_API int SXT_CALL sxt_hash_keybytes_min(void) { return (int)crypto_generichash_KEYBYTES_MIN; }
SXT_API int SXT_CALL sxt_hash_keybytes_max(void) { return (int)crypto_generichash_KEYBYTES_MAX; }

SXT_API int SXT_CALL sxt_base64_variant_original(void)
{ return sodium_base64_VARIANT_ORIGINAL; }
SXT_API int SXT_CALL sxt_base64_variant_original_no_padding(void)
{ return sodium_base64_VARIANT_ORIGINAL_NO_PADDING; }
SXT_API int SXT_CALL sxt_base64_variant_urlsafe(void)
{ return sodium_base64_VARIANT_URLSAFE; }
SXT_API int SXT_CALL sxt_base64_variant_urlsafe_no_padding(void)
{ return sodium_base64_VARIANT_URLSAFE_NO_PADDING; }

static int valid_b64_variant(int v)
{
    return v == sodium_base64_VARIANT_ORIGINAL
        || v == sodium_base64_VARIANT_ORIGINAL_NO_PADDING
        || v == sodium_base64_VARIANT_URLSAFE
        || v == sodium_base64_VARIANT_URLSAFE_NO_PADDING;
}

SXT_API int SXT_CALL sxt_generichash(unsigned char *out, int cap, int outlen,
                                     const unsigned char *in, int inlen,
                                     const unsigned char *key, int keylen)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (inlen < 0 || keylen < 0) {
        set_error("sxt_generichash: negative length");
        return SXT_ERR_BADARG;
    }
    if (outlen < (int)crypto_generichash_BYTES_MIN ||
        outlen > (int)crypto_generichash_BYTES_MAX) {
        set_error("sxt_generichash: digest length out of range");
        return SXT_ERR_BADARG;
    }
    if (keylen > 0 && (keylen < (int)crypto_generichash_KEYBYTES_MIN ||
                       keylen > (int)crypto_generichash_KEYBYTES_MAX)) {
        set_error("sxt_generichash: key length out of range");
        return SXT_ERR_BADARG;
    }
    if (cap < outlen) {
        return -outlen;
    }
    if (out == NULL) {
        set_error("sxt_generichash: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (inlen > 0 && in == NULL) {
        set_error("sxt_generichash: null input");
        return SXT_ERR_BADARG;
    }
    if (keylen > 0 && key == NULL) {
        set_error("sxt_generichash: null key");
        return SXT_ERR_BADARG;
    }
    if (crypto_generichash(out, (size_t)outlen, in, (unsigned long long)inlen,
                           (keylen > 0 ? key : NULL), (size_t)keylen) != 0) {
        set_error("sxt_generichash: hashing failed");
        return SXT_ERR_BADARG;
    }
    return outlen;
}

SXT_API int SXT_CALL sxt_bin2hex(char *out, int cap,
                                 const unsigned char *in, int inlen)
{
    int needed;
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (inlen < 0) {
        set_error("sxt_bin2hex: negative length");
        return SXT_ERR_BADARG;
    }
    /* hex is inlen*2 chars plus a NUL; guard the multiply against overflow. */
    if (inlen > (SXT_MAX_BUFFER - 1) / 2) {
        set_error("sxt_bin2hex: input too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    needed = inlen * 2 + 1;                 /* sodium_bin2hex needs room for NUL */
    if (cap < needed) {
        return -needed;
    }
    if (out == NULL) {
        set_error("sxt_bin2hex: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (inlen > 0 && in == NULL) {
        set_error("sxt_bin2hex: null input");
        return SXT_ERR_BADARG;
    }
    sodium_bin2hex(out, (size_t)cap, in, (size_t)inlen);
    return inlen * 2;                       /* string length, excluding the NUL */
}

SXT_API int SXT_CALL sxt_hex2bin(unsigned char *out, int cap,
                                 const char *hex, int hexlen)
{
    int needed;
    size_t bin_len = 0;
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (hexlen < 0) {
        set_error("sxt_hex2bin: negative length");
        return SXT_ERR_BADARG;
    }
    needed = hexlen / 2;                     /* upper bound on decoded bytes */
    if (cap < needed) {
        return -needed;
    }
    if (needed > 0 && out == NULL) {
        set_error("sxt_hex2bin: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (hexlen > 0 && hex == NULL) {
        set_error("sxt_hex2bin: null input");
        return SXT_ERR_BADARG;
    }
    /* ignore = NULL (no separator chars tolerated), hex_end = NULL (the whole
     * input must be valid hex), so a stray character is a clean ENCODING error,
     * never a partial decode. */
    if (sodium_hex2bin(out, (size_t)cap, hex, (size_t)hexlen,
                       NULL, &bin_len, NULL) != 0) {
        set_error("sxt_hex2bin: malformed hex input");
        return SXT_ERR_ENCODING;
    }
    return (int)bin_len;
}

SXT_API int SXT_CALL sxt_bin2base64(char *out, int cap,
                                    const unsigned char *in, int inlen, int variant)
{
    int needed;
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (inlen < 0) {
        set_error("sxt_bin2base64: negative length");
        return SXT_ERR_BADARG;
    }
    if (!valid_b64_variant(variant)) {
        set_error("sxt_bin2base64: unknown base64 variant");
        return SXT_ERR_BADARG;
    }
    /* sodium_base64_encoded_len already includes room for the NUL. */
    needed = (int)sodium_base64_encoded_len((size_t)inlen, variant);
    if (cap < needed) {
        return -needed;
    }
    if (out == NULL) {
        set_error("sxt_bin2base64: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (inlen > 0 && in == NULL) {
        set_error("sxt_bin2base64: null input");
        return SXT_ERR_BADARG;
    }
    sodium_bin2base64(out, (size_t)cap, in, (size_t)inlen, variant);
    return (int)strlen(out);                 /* actual string length sans NUL */
}

SXT_API int SXT_CALL sxt_base642bin(unsigned char *out, int cap,
                                    const char *b64, int b64len, int variant)
{
    int needed;
    size_t bin_len = 0;
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (b64len < 0) {
        set_error("sxt_base642bin: negative length");
        return SXT_ERR_BADARG;
    }
    if (!valid_b64_variant(variant)) {
        set_error("sxt_base642bin: unknown base64 variant");
        return SXT_ERR_BADARG;
    }
    /* decoded bytes are at most 3 per 4 base64 chars; +3 covers any remainder. */
    needed = (b64len / 4) * 3 + 3;
    if (cap < needed) {
        return -needed;
    }
    if (out == NULL) {
        set_error("sxt_base642bin: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (b64len > 0 && b64 == NULL) {
        set_error("sxt_base642bin: null input");
        return SXT_ERR_BADARG;
    }
    if (sodium_base642bin(out, (size_t)cap, b64, (size_t)b64len,
                          NULL, &bin_len, NULL, variant) != 0) {
        set_error("sxt_base642bin: malformed base64 input");
        return SXT_ERR_ENCODING;
    }
    return (int)bin_len;
}

SXT_API int SXT_CALL sxt_memequal(const unsigned char *a, int alen,
                                  const unsigned char *b, int blen)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return 0;                            /* conservative: treat as not equal */
    }
    if (alen < 0 || blen < 0) {
        return 0;
    }
    if (alen != blen) {
        return 0;                            /* length is not secret */
    }
    if (alen == 0) {
        return 1;                            /* two empty buffers are equal */
    }
    if (a == NULL || b == NULL) {
        return 0;
    }
    return sodium_memcmp(a, b, (size_t)alen) == 0 ? 1 : 0;
}

/* ========================================================================== *
 * Phase 2: secret-key authenticated encryption + Argon2id.
 * ========================================================================== */

SXT_API int SXT_CALL sxt_secretbox_keybytes(void)   { return (int)crypto_secretbox_KEYBYTES; }
SXT_API int SXT_CALL sxt_secretbox_noncebytes(void) { return (int)crypto_secretbox_NONCEBYTES; }
SXT_API int SXT_CALL sxt_secretbox_macbytes(void)   { return (int)crypto_secretbox_MACBYTES; }

SXT_API int SXT_CALL sxt_secretbox(unsigned char *out, int cap,
                                   const unsigned char *msg, int msglen,
                                   const unsigned char *key, int keylen)
{
    const int noncebytes = (int)crypto_secretbox_NONCEBYTES;
    const int macbytes = (int)crypto_secretbox_MACBYTES;
    int needed;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (msglen < 0) {
        set_error("sxt_secretbox: negative length");
        return SXT_ERR_BADARG;
    }
    if (keylen != (int)crypto_secretbox_KEYBYTES) {
        set_error("sxt_secretbox: wrong key length");
        return SXT_ERR_BADARG;
    }
    /* Guard the framed length against int overflow before we negate it. */
    if (msglen > SXT_MAX_BUFFER - noncebytes - macbytes) {
        set_error("sxt_secretbox: message too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    needed = noncebytes + msglen + macbytes;
    if (cap < needed) {
        return -needed;
    }
    if (out == NULL || key == NULL) {
        set_error("sxt_secretbox: null buffer");
        return SXT_ERR_BADARG;
    }
    if (msglen > 0 && msg == NULL) {
        set_error("sxt_secretbox: null message");
        return SXT_ERR_BADARG;
    }
    /* Fresh random nonce, written into the first noncebytes of out, then the
     * ciphertext+MAC after it. The nonce is public; the key never moves. */
    randombytes_buf(out, (size_t)noncebytes);
    if (crypto_secretbox_easy(out + noncebytes, msg, (unsigned long long)msglen,
                              out, key) != 0) {
        set_error("sxt_secretbox: encryption failed");
        return SXT_ERR_BADARG;
    }
    return needed;
}

SXT_API int SXT_CALL sxt_secretbox_open(unsigned char *out, int cap,
                                        const unsigned char *box, int boxlen,
                                        const unsigned char *key, int keylen)
{
    const int noncebytes = (int)crypto_secretbox_NONCEBYTES;
    const int macbytes = (int)crypto_secretbox_MACBYTES;
    int plainlen;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (keylen != (int)crypto_secretbox_KEYBYTES) {
        set_error("sxt_secretbox_open: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (boxlen < noncebytes + macbytes) {
        set_error("sxt_secretbox_open: ciphertext too short");
        return SXT_ERR_BADARG;
    }
    plainlen = boxlen - noncebytes - macbytes;
    if (cap < plainlen) {
        return -plainlen;
    }
    if (box == NULL || key == NULL) {
        set_error("sxt_secretbox_open: null buffer");
        return SXT_ERR_BADARG;
    }
    if (plainlen > 0 && out == NULL) {
        set_error("sxt_secretbox_open: null output buffer");
        return SXT_ERR_BADARG;
    }
    /* The leading noncebytes are the nonce; verify+decrypt the rest. A bad tag
     * (wrong key or tampering) is reported as SXT_ERR_AUTH, never as garbage. */
    if (crypto_secretbox_open_easy(out, box + noncebytes,
                                   (unsigned long long)(boxlen - noncebytes),
                                   box, key) != 0) {
        set_error("sxt_secretbox_open: wrong key or tampered data");
        return SXT_ERR_AUTH;
    }
    return plainlen;
}

SXT_API int SXT_CALL sxt_aead_keybytes(void)
{ return (int)crypto_aead_xchacha20poly1305_ietf_KEYBYTES; }
SXT_API int SXT_CALL sxt_aead_noncebytes(void)
{ return (int)crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; }
SXT_API int SXT_CALL sxt_aead_abytes(void)
{ return (int)crypto_aead_xchacha20poly1305_ietf_ABYTES; }

SXT_API int SXT_CALL sxt_aead_encrypt(unsigned char *out, int cap,
                                      const unsigned char *msg, int msglen,
                                      const unsigned char *ad, int adlen,
                                      const unsigned char *key, int keylen)
{
    const int npub = (int)crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const int abytes = (int)crypto_aead_xchacha20poly1305_ietf_ABYTES;
    int needed;
    unsigned long long clen = 0;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (msglen < 0 || adlen < 0) {
        set_error("sxt_aead_encrypt: negative length");
        return SXT_ERR_BADARG;
    }
    if (keylen != (int)crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        set_error("sxt_aead_encrypt: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (msglen > SXT_MAX_BUFFER - npub - abytes) {
        set_error("sxt_aead_encrypt: message too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    needed = npub + msglen + abytes;
    if (cap < needed) {
        return -needed;
    }
    if (out == NULL || key == NULL) {
        set_error("sxt_aead_encrypt: null buffer");
        return SXT_ERR_BADARG;
    }
    if (msglen > 0 && msg == NULL) {
        set_error("sxt_aead_encrypt: null message");
        return SXT_ERR_BADARG;
    }
    if (adlen > 0 && ad == NULL) {
        set_error("sxt_aead_encrypt: null associated data");
        return SXT_ERR_BADARG;
    }
    randombytes_buf(out, (size_t)npub);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out + npub, &clen, msg, (unsigned long long)msglen,
            ad, (unsigned long long)adlen, NULL, out, key) != 0) {
        set_error("sxt_aead_encrypt: encryption failed");
        return SXT_ERR_BADARG;
    }
    return npub + (int)clen;
}

SXT_API int SXT_CALL sxt_aead_decrypt(unsigned char *out, int cap,
                                      const unsigned char *box, int boxlen,
                                      const unsigned char *ad, int adlen,
                                      const unsigned char *key, int keylen)
{
    const int npub = (int)crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const int abytes = (int)crypto_aead_xchacha20poly1305_ietf_ABYTES;
    int plainlen;
    unsigned long long mlen = 0;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (adlen < 0) {
        set_error("sxt_aead_decrypt: negative length");
        return SXT_ERR_BADARG;
    }
    if (keylen != (int)crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        set_error("sxt_aead_decrypt: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (boxlen < npub + abytes) {
        set_error("sxt_aead_decrypt: ciphertext too short");
        return SXT_ERR_BADARG;
    }
    plainlen = boxlen - npub - abytes;
    if (cap < plainlen) {
        return -plainlen;
    }
    if (box == NULL || key == NULL) {
        set_error("sxt_aead_decrypt: null buffer");
        return SXT_ERR_BADARG;
    }
    if (plainlen > 0 && out == NULL) {
        set_error("sxt_aead_decrypt: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (adlen > 0 && ad == NULL) {
        set_error("sxt_aead_decrypt: null associated data");
        return SXT_ERR_BADARG;
    }
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            out, &mlen, NULL, box + npub, (unsigned long long)(boxlen - npub),
            ad, (unsigned long long)adlen, box, key) != 0) {
        set_error("sxt_aead_decrypt: wrong key, wrong associated data, or tampered");
        return SXT_ERR_AUTH;
    }
    return (int)mlen;
}

/* ---- Argon2id (crypto_pwhash) ------------------------------------------- */

SXT_API int SXT_CALL sxt_pwhash_saltbytes(void) { return (int)crypto_pwhash_SALTBYTES; }
SXT_API int SXT_CALL sxt_pwhash_bytes_min(void) { return (int)crypto_pwhash_BYTES_MIN; }
SXT_API int SXT_CALL sxt_pwhash_strbytes(void)  { return (int)crypto_pwhash_STRBYTES; }

SXT_API int SXT_CALL sxt_pwhash_opslimit_interactive(void)
{ return (int)crypto_pwhash_OPSLIMIT_INTERACTIVE; }
SXT_API int SXT_CALL sxt_pwhash_opslimit_moderate(void)
{ return (int)crypto_pwhash_OPSLIMIT_MODERATE; }
SXT_API int SXT_CALL sxt_pwhash_opslimit_sensitive(void)
{ return (int)crypto_pwhash_OPSLIMIT_SENSITIVE; }

/* memlimit presets as decimal strings (SENSITIVE is 1 GiB now and could grow
 * past 2^31 in a future libsodium). Each has its own static buffer so the three
 * results never alias; the LCB layer copies the ZStringUTF8 on return anyway. */
SXT_API const char *SXT_CALL sxt_pwhash_memlimit_interactive(void)
{
    static char buf[24];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)crypto_pwhash_MEMLIMIT_INTERACTIVE);
    return buf;
}
SXT_API const char *SXT_CALL sxt_pwhash_memlimit_moderate(void)
{
    static char buf[24];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)crypto_pwhash_MEMLIMIT_MODERATE);
    return buf;
}
SXT_API const char *SXT_CALL sxt_pwhash_memlimit_sensitive(void)
{
    static char buf[24];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)crypto_pwhash_MEMLIMIT_SENSITIVE);
    return buf;
}

/* Parse a decimal unsigned 64-bit value; 0 on success, -1 on any malformation
 * (empty, non-digit, overflow). 64-bit limits cross the FFI as strings because
 * there is no 64-bit foreign int (CLAUDE.md). */
static int parse_u64(const char *s, unsigned long long *out)
{
    char *end = NULL;
    unsigned long long v;
    if (s == NULL || *s == '\0') {
        return -1;
    }
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return -1;
    }
    *out = v;
    return 0;
}

/* Parse + range-check opslimit/memlimit against libsodium's own bounds. */
static int parse_limits(const char *opslimit, const char *memlimit,
                        unsigned long long *ops, unsigned long long *mem)
{
    if (parse_u64(opslimit, ops) != 0 || parse_u64(memlimit, mem) != 0) {
        set_error("pwhash: opslimit/memlimit not a valid decimal number");
        return -1;
    }
    if (*ops < crypto_pwhash_OPSLIMIT_MIN || *ops > crypto_pwhash_OPSLIMIT_MAX) {
        set_error("pwhash: opslimit out of range");
        return -1;
    }
    if (*mem < crypto_pwhash_MEMLIMIT_MIN || *mem > crypto_pwhash_MEMLIMIT_MAX) {
        set_error("pwhash: memlimit out of range");
        return -1;
    }
    return 0;
}

SXT_API int SXT_CALL sxt_pwhash(unsigned char *out, int cap, int outlen,
                                const unsigned char *pass, int passlen,
                                const unsigned char *salt, int saltlen,
                                const char *opslimit, const char *memlimit)
{
    unsigned long long ops = 0;
    unsigned long long mem = 0;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (passlen < 0) {
        set_error("sxt_pwhash: negative passphrase length");
        return SXT_ERR_BADARG;
    }
    if (outlen < (int)crypto_pwhash_BYTES_MIN || outlen >= SXT_MAX_BUFFER) {
        set_error("sxt_pwhash: derived key length out of range");
        return SXT_ERR_BADARG;
    }
    if (saltlen != (int)crypto_pwhash_SALTBYTES) {
        set_error("sxt_pwhash: wrong salt length");
        return SXT_ERR_BADARG;
    }
    if (parse_limits(opslimit, memlimit, &ops, &mem) != 0) {
        return SXT_ERR_BADARG;
    }
    if (cap < outlen) {
        return -outlen;
    }
    if (out == NULL || salt == NULL) {
        set_error("sxt_pwhash: null buffer");
        return SXT_ERR_BADARG;
    }
    if (passlen > 0 && pass == NULL) {
        set_error("sxt_pwhash: null passphrase");
        return SXT_ERR_BADARG;
    }
    /* Argon2id: the only sanctioned password KDF. A non-zero return is almost
     * always "could not allocate memlimit bytes"; surface it, do not crash. */
    if (crypto_pwhash(out, (unsigned long long)outlen,
                      (const char *)pass, (unsigned long long)passlen,
                      salt, ops, (size_t)mem, crypto_pwhash_ALG_ARGON2ID13) != 0) {
        set_error("sxt_pwhash: derivation failed (out of memory for memlimit?)");
        return SXT_ERR_BADARG;
    }
    return outlen;
}

SXT_API int SXT_CALL sxt_pwhash_str(char *out, int cap,
                                    const unsigned char *pass, int passlen,
                                    const char *opslimit, const char *memlimit)
{
    unsigned long long ops = 0;
    unsigned long long mem = 0;
    const int needed = (int)crypto_pwhash_STRBYTES;   /* includes the NUL */

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (passlen < 0) {
        set_error("sxt_pwhash_str: negative passphrase length");
        return SXT_ERR_BADARG;
    }
    if (parse_limits(opslimit, memlimit, &ops, &mem) != 0) {
        return SXT_ERR_BADARG;
    }
    if (cap < needed) {
        return -needed;
    }
    if (out == NULL) {
        set_error("sxt_pwhash_str: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (passlen > 0 && pass == NULL) {
        set_error("sxt_pwhash_str: null passphrase");
        return SXT_ERR_BADARG;
    }
    if (crypto_pwhash_str(out, (const char *)pass, (unsigned long long)passlen,
                          ops, (size_t)mem) != 0) {
        set_error("sxt_pwhash_str: hashing failed (out of memory for memlimit?)");
        return SXT_ERR_BADARG;
    }
    return (int)strlen(out);
}

SXT_API int SXT_CALL sxt_pwhash_str_verify(const char *hashstr,
                                           const unsigned char *pass, int passlen)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return 0;
    }
    if (hashstr == NULL || passlen < 0 || (passlen > 0 && pass == NULL)) {
        return 0;
    }
    /* A non-match (or a malformed stored string) is a legitimate 0, not an error
     * in the band: "wrong password" is an answer the caller acts on. */
    return crypto_pwhash_str_verify(hashstr, (const char *)pass,
                                    (unsigned long long)passlen) == 0 ? 1 : 0;
}
