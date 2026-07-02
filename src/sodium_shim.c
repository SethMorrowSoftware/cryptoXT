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

/*
 * Copy a NUL-terminated C string into the caller's out buffer using the same
 * overloaded-return contract as the byte-buffer fills:
 *   - cap too small           -> -(len+1)        (-needed, includes the NUL)
 *   - out == NULL (with room)  -> SXT_ERR_BADARG
 *   - otherwise               -> write len bytes + NUL, return len.
 *
 * Why this exists: a C string must NEVER cross the FFI as a foreign RETURN
 * value. The LCB engine ADOPTS a returned ZStringUTF8 / NativeCString / WString
 * pointer and later calls free() on it (every bridged-C-string foreign type
 * registers free() as its finalizer in the engine), so returning a static
 * literal or a library-owned string is free()-on-static: heap corruption on the
 * first call. Instead the caller hands us an MCMemoryAllocate block and we fill
 * it, exactly like sxt_bin2hex; the engine owns and frees that block. This
 * helper is deliberately mechanical (it never touches s_last_error) so
 * sxt_last_error can reuse it without clobbering the message it is reporting.
 */
static int fill_string(char *out, int cap, const char *src)
{
    size_t len = (src != NULL) ? strlen(src) : 0;
    if (len >= (size_t)SXT_MAX_BUFFER) {
        return SXT_ERR_BADARG;          /* unreachable for our tiny strings */
    }
    if (cap < (int)len + 1) {
        return -((int)len + 1);
    }
    if (out == NULL) {
        return SXT_ERR_BADARG;
    }
    if (len > 0) {
        memcpy(out, src, len);
    }
    out[len] = '\0';
    return (int)len;
}

SXT_API int SXT_CALL sxt_version(char *out, int cap)
{
    return fill_string(out, cap, "0.1.0");
}

SXT_API int SXT_CALL sxt_sodium_version(char *out, int cap)
{
    /* Guard on init only so we never query libsodium before it is ready; on a
     * failed init report the empty string rather than an error code. */
    if (ensure_init() != SXT_OK) {
        return fill_string(out, cap, "");
    }
    return fill_string(out, cap, sodium_version_string());
}

SXT_API int SXT_CALL sxt_abi_version(void)
{
    return SXT_ABI_VERSION;
}

SXT_API int SXT_CALL sxt_last_error(char *out, int cap)
{
    /* s_last_error is the empty string when clean, so this naturally returns 0
     * (length) for a clean call. A pure read: fill_string never mutates it. */
    return fill_string(out, cap, s_last_error);
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
    if (inlen >= (SXT_MAX_BUFFER - 1) / 2) {
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
    /* base64 expands by ~4/3 plus a NUL; bound the input so the encoded length
     * stays below SXT_MAX_BUFFER (and so the (int) cast below cannot overflow),
     * the same firewall sxt_bin2hex applies to its 2x expansion. */
    if (inlen >= SXT_MAX_BUFFER / 2) {
        set_error("sxt_bin2base64: input too large for a single buffer");
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
    if (msglen >= SXT_MAX_BUFFER - noncebytes - macbytes) {
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
    /* Keep the size query (-plainlen) strictly inside the -needed band so it can
     * never alias a hard-error code, exactly as the encrypt side bounds msglen. */
    if (boxlen >= SXT_MAX_BUFFER) {
        set_error("sxt_secretbox_open: ciphertext too large for a single buffer");
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
    if (msglen >= SXT_MAX_BUFFER - npub - abytes) {
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
    if (boxlen >= SXT_MAX_BUFFER) {   /* keep -plainlen inside the -needed band */
        set_error("sxt_aead_decrypt: ciphertext too large for a single buffer");
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
 * past 2^31 in a future libsodium), filled into the caller's buffer. We format
 * into a local scratch buffer and copy out via fill_string: never return a
 * pointer to it (a returned C string would be free()d by the engine; see
 * fill_string). */
SXT_API int SXT_CALL sxt_pwhash_memlimit_interactive(char *out, int cap)
{
    char buf[24];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)crypto_pwhash_MEMLIMIT_INTERACTIVE);
    return fill_string(out, cap, buf);
}
SXT_API int SXT_CALL sxt_pwhash_memlimit_moderate(char *out, int cap)
{
    char buf[24];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)crypto_pwhash_MEMLIMIT_MODERATE);
    return fill_string(out, cap, buf);
}
SXT_API int SXT_CALL sxt_pwhash_memlimit_sensitive(char *out, int cap)
{
    char buf[24];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)crypto_pwhash_MEMLIMIT_SENSITIVE);
    return fill_string(out, cap, buf);
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

/* ========================================================================== *
 * Phase 3: streaming AEAD (secretstream) + file helpers.
 * ========================================================================== */

SXT_API int SXT_CALL sxt_secretstream_keybytes(void)
{ return (int)crypto_secretstream_xchacha20poly1305_KEYBYTES; }
SXT_API int SXT_CALL sxt_secretstream_headerbytes(void)
{ return (int)crypto_secretstream_xchacha20poly1305_HEADERBYTES; }
SXT_API int SXT_CALL sxt_secretstream_abytes(void)
{ return (int)crypto_secretstream_xchacha20poly1305_ABYTES; }
SXT_API int SXT_CALL sxt_secretstream_tag_message(void)
{ return crypto_secretstream_xchacha20poly1305_TAG_MESSAGE; }
SXT_API int SXT_CALL sxt_secretstream_tag_final(void)
{ return crypto_secretstream_xchacha20poly1305_TAG_FINAL; }

/*
 * Generation-tagged handle table (CLAUDE.md "Handles for the stateful
 * primitives"). The engine is single-threaded, so no locking is needed. A
 * handle packs a 14-bit generation and a 1-based slot index; freeing a slot
 * bumps its generation, so every previously issued handle for that slot fails
 * lookup afterwards (a clean error, never a use-after-free). Handles are always
 * positive (>= 65537), so they never collide with a negative -needed/error.
 */
#define SXT_STREAM_SLOTS 64
#define SXT_STREAM_MODE_PUSH 1
#define SXT_STREAM_MODE_PULL 2

typedef struct {
    int in_use;
    int gen;        /* current generation; starts at 1, bumped on free */
    int mode;       /* SXT_STREAM_MODE_PUSH or _PULL */
    int last_tag;   /* tag from the most recent successful pull, else -1 */
    crypto_secretstream_xchacha20poly1305_state state;
} sxt_stream_slot;

static sxt_stream_slot s_streams[SXT_STREAM_SLOTS];

static int stream_make_handle(int idx, int gen)
{
    return ((gen & 0x3FFF) << 16) | ((idx + 1) & 0xFFFF);
}

static sxt_stream_slot *stream_lookup(int handle, int want_mode)
{
    int idx = (handle & 0xFFFF) - 1;
    int gen = (handle >> 16) & 0x3FFF;
    sxt_stream_slot *slot;
    if (idx < 0 || idx >= SXT_STREAM_SLOTS) {
        return NULL;
    }
    slot = &s_streams[idx];
    if (!slot->in_use || slot->gen != gen) {
        return NULL;                 /* stale or recycled handle */
    }
    if (want_mode != 0 && slot->mode != want_mode) {
        return NULL;                 /* wrong direction (push vs pull) */
    }
    return slot;
}

static int stream_alloc(int mode)
{
    int i;
    for (i = 0; i < SXT_STREAM_SLOTS; i++) {
        if (!s_streams[i].in_use) {
            if (s_streams[i].gen <= 0) {
                s_streams[i].gen = 1;
            }
            s_streams[i].in_use = 1;
            s_streams[i].mode = mode;
            s_streams[i].last_tag = -1;
            return stream_make_handle(i, s_streams[i].gen);
        }
    }
    return 0;                        /* table full */
}

SXT_API void SXT_CALL sxt_free_stream(int handle)
{
    int idx = (handle & 0xFFFF) - 1;
    int gen = (handle >> 16) & 0x3FFF;
    if (idx < 0 || idx >= SXT_STREAM_SLOTS) {
        return;                      /* unknown handle: clean no-op */
    }
    if (!s_streams[idx].in_use || s_streams[idx].gen != gen) {
        return;                      /* already freed / stale: idempotent no-op */
    }
    sodium_memzero(&s_streams[idx].state, sizeof(s_streams[idx].state));
    s_streams[idx].in_use = 0;
    s_streams[idx].last_tag = -1;
    s_streams[idx].gen++;            /* invalidate every outstanding handle */
    if (s_streams[idx].gen > 0x3FFF) {
        s_streams[idx].gen = 1;      /* wrap, staying positive */
    }
}

SXT_API int SXT_CALL sxt_secretstream_init_push(unsigned char *header_out, int header_cap,
                                                const unsigned char *key, int keylen)
{
    const int hb = (int)crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    int handle;
    sxt_stream_slot *slot;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (keylen != (int)crypto_secretstream_xchacha20poly1305_KEYBYTES) {
        set_error("sxt_secretstream_init_push: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (header_cap < hb) {
        return -hb;
    }
    if (header_out == NULL || key == NULL) {
        set_error("sxt_secretstream_init_push: null buffer");
        return SXT_ERR_BADARG;
    }
    handle = stream_alloc(SXT_STREAM_MODE_PUSH);
    if (handle == 0) {
        set_error("sxt_secretstream_init_push: too many open streams");
        return SXT_ERR_BADARG;
    }
    slot = stream_lookup(handle, SXT_STREAM_MODE_PUSH);
    if (slot == NULL ||
        crypto_secretstream_xchacha20poly1305_init_push(&slot->state, header_out, key) != 0) {
        sxt_free_stream(handle);
        set_error("sxt_secretstream_init_push: init failed");
        return SXT_ERR_BADARG;
    }
    return handle;
}

SXT_API int SXT_CALL sxt_secretstream_push(int handle, unsigned char *out, int cap,
                                           const unsigned char *chunk, int chunklen,
                                           const unsigned char *ad, int adlen, int tag)
{
    const int ab = (int)crypto_secretstream_xchacha20poly1305_ABYTES;
    sxt_stream_slot *slot;
    unsigned long long clen = 0;
    int needed;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (chunklen < 0 || adlen < 0) {
        set_error("sxt_secretstream_push: negative length");
        return SXT_ERR_BADARG;
    }
    if (tag != crypto_secretstream_xchacha20poly1305_TAG_MESSAGE &&
        tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL &&
        tag != crypto_secretstream_xchacha20poly1305_TAG_PUSH &&
        tag != crypto_secretstream_xchacha20poly1305_TAG_REKEY) {
        set_error("sxt_secretstream_push: unknown tag");
        return SXT_ERR_BADARG;
    }
    slot = stream_lookup(handle, SXT_STREAM_MODE_PUSH);
    if (slot == NULL) {
        set_error("sxt_secretstream_push: bad or wrong-mode handle");
        return SXT_ERR_BADHANDLE;
    }
    if (chunklen >= SXT_MAX_BUFFER - ab) {
        set_error("sxt_secretstream_push: chunk too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    needed = chunklen + ab;
    if (cap < needed) {
        return -needed;
    }
    if (out == NULL) {
        set_error("sxt_secretstream_push: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (chunklen > 0 && chunk == NULL) {
        set_error("sxt_secretstream_push: null chunk");
        return SXT_ERR_BADARG;
    }
    if (adlen > 0 && ad == NULL) {
        set_error("sxt_secretstream_push: null associated data");
        return SXT_ERR_BADARG;
    }
    if (crypto_secretstream_xchacha20poly1305_push(
            &slot->state, out, &clen, chunk, (unsigned long long)chunklen,
            ad, (unsigned long long)adlen, (unsigned char)tag) != 0) {
        set_error("sxt_secretstream_push: encryption failed");
        return SXT_ERR_BADARG;
    }
    return (int)clen;
}

SXT_API int SXT_CALL sxt_secretstream_init_pull(const unsigned char *header, int headerlen,
                                                const unsigned char *key, int keylen)
{
    const int hb = (int)crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    int handle;
    sxt_stream_slot *slot;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (keylen != (int)crypto_secretstream_xchacha20poly1305_KEYBYTES) {
        set_error("sxt_secretstream_init_pull: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (headerlen != hb) {
        set_error("sxt_secretstream_init_pull: wrong header length");
        return SXT_ERR_BADARG;
    }
    if (header == NULL || key == NULL) {
        set_error("sxt_secretstream_init_pull: null buffer");
        return SXT_ERR_BADARG;
    }
    handle = stream_alloc(SXT_STREAM_MODE_PULL);
    if (handle == 0) {
        set_error("sxt_secretstream_init_pull: too many open streams");
        return SXT_ERR_BADARG;
    }
    slot = stream_lookup(handle, SXT_STREAM_MODE_PULL);
    if (slot == NULL ||
        crypto_secretstream_xchacha20poly1305_init_pull(&slot->state, header, key) != 0) {
        sxt_free_stream(handle);
        set_error("sxt_secretstream_init_pull: malformed header");
        return SXT_ERR_BADARG;
    }
    return handle;
}

SXT_API int SXT_CALL sxt_secretstream_pull(int handle, unsigned char *out, int cap,
                                           const unsigned char *in, int inlen,
                                           const unsigned char *ad, int adlen)
{
    const int ab = (int)crypto_secretstream_xchacha20poly1305_ABYTES;
    sxt_stream_slot *slot;
    unsigned long long mlen = 0;
    unsigned char tag = 0;
    int plainlen;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (adlen < 0) {
        set_error("sxt_secretstream_pull: negative length");
        return SXT_ERR_BADARG;
    }
    slot = stream_lookup(handle, SXT_STREAM_MODE_PULL);
    if (slot == NULL) {
        set_error("sxt_secretstream_pull: bad or wrong-mode handle");
        return SXT_ERR_BADHANDLE;
    }
    if (inlen < ab) {
        set_error("sxt_secretstream_pull: chunk too short");
        return SXT_ERR_BADARG;
    }
    if (inlen >= SXT_MAX_BUFFER) {   /* keep -plainlen inside the -needed band */
        set_error("sxt_secretstream_pull: chunk too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    plainlen = inlen - ab;
    if (cap < plainlen) {
        return -plainlen;
    }
    if (in == NULL) {
        set_error("sxt_secretstream_pull: null input");
        return SXT_ERR_BADARG;
    }
    if (plainlen > 0 && out == NULL) {
        set_error("sxt_secretstream_pull: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (adlen > 0 && ad == NULL) {
        set_error("sxt_secretstream_pull: null associated data");
        return SXT_ERR_BADARG;
    }
    if (crypto_secretstream_xchacha20poly1305_pull(
            &slot->state, out, &mlen, &tag, in, (unsigned long long)inlen,
            ad, (unsigned long long)adlen) != 0) {
        set_error("sxt_secretstream_pull: wrong key or tampered chunk");
        return SXT_ERR_AUTH;
    }
    slot->last_tag = (int)tag;
    return (int)mlen;
}

SXT_API int SXT_CALL sxt_secretstream_last_tag(int handle)
{
    sxt_stream_slot *slot;
    clear_error();
    slot = stream_lookup(handle, 0);
    if (slot == NULL) {
        set_error("sxt_secretstream_last_tag: bad handle");
        return SXT_ERR_BADHANDLE;
    }
    return slot->last_tag;
}

SXT_API int SXT_CALL sxt_secretstream_rekey(int handle)
{
    sxt_stream_slot *slot;
    clear_error();
    /* Works on either direction: both push and pull rekey their own state at the
     * matching point in the stream. want_mode 0 accepts a push or a pull slot. */
    slot = stream_lookup(handle, 0);
    if (slot == NULL) {
        set_error("sxt_secretstream_rekey: bad or wrong-mode handle");
        return SXT_ERR_BADHANDLE;
    }
    crypto_secretstream_xchacha20poly1305_rekey(&slot->state);
    return SXT_OK;
}

/* ---- File helpers (pure C; the plaintext never enters a LiveCode Data) --- */

#define SXT_FILE_CHUNK 16384

SXT_API int SXT_CALL sxt_encrypt_file(const char *src_path, const char *dst_path,
                                      const unsigned char *key, int keylen)
{
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    unsigned char in[SXT_FILE_CHUNK];
    unsigned char out[SXT_FILE_CHUNK + crypto_secretstream_xchacha20poly1305_ABYTES];
    FILE *fsrc = NULL;
    FILE *fdst = NULL;
    size_t rlen;
    unsigned long long clen;
    unsigned char tag;
    int eof;
    int rc = SXT_OK;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (keylen != (int)crypto_secretstream_xchacha20poly1305_KEYBYTES) {
        set_error("sxt_encrypt_file: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (src_path == NULL || dst_path == NULL || key == NULL) {
        set_error("sxt_encrypt_file: null path or key");
        return SXT_ERR_BADARG;
    }
    fsrc = fopen(src_path, "rb");
    if (fsrc == NULL) {
        set_error("sxt_encrypt_file: cannot open source file");
        return SXT_ERR_IO;
    }
    fdst = fopen(dst_path, "wb");
    if (fdst == NULL) {
        fclose(fsrc);
        set_error("sxt_encrypt_file: cannot open destination file");
        return SXT_ERR_IO;
    }

    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    if (fwrite(header, 1, sizeof(header), fdst) != sizeof(header)) {
        set_error("sxt_encrypt_file: write error");
        rc = SXT_ERR_IO;
    } else {
        do {
            rlen = fread(in, 1, sizeof(in), fsrc);
            if (ferror(fsrc)) {
                set_error("sxt_encrypt_file: read error");
                rc = SXT_ERR_IO;
                break;
            }
            eof = feof(fsrc);
            tag = eof ? (unsigned char)crypto_secretstream_xchacha20poly1305_TAG_FINAL
                      : (unsigned char)crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
            crypto_secretstream_xchacha20poly1305_push(&st, out, &clen, in,
                                                       (unsigned long long)rlen,
                                                       NULL, 0, tag);
            if (fwrite(out, 1, (size_t)clen, fdst) != (size_t)clen) {
                set_error("sxt_encrypt_file: write error");
                rc = SXT_ERR_IO;
                break;
            }
        } while (!eof);
    }

    sodium_memzero(&st, sizeof(st));
    sodium_memzero(in, sizeof(in));
    sodium_memzero(out, sizeof(out));
    if (fclose(fdst) != 0 && rc == SXT_OK) {
        set_error("sxt_encrypt_file: close error");
        rc = SXT_ERR_IO;
    }
    fclose(fsrc);
    if (rc != SXT_OK) {
        remove(dst_path);                /* never leave a partial ciphertext */
    }
    return rc;
}

SXT_API int SXT_CALL sxt_decrypt_file(const char *src_path, const char *dst_path,
                                      const unsigned char *key, int keylen)
{
    const int ab = (int)crypto_secretstream_xchacha20poly1305_ABYTES;
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    unsigned char in[SXT_FILE_CHUNK + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char out[SXT_FILE_CHUNK];
    FILE *fsrc = NULL;
    FILE *fdst = NULL;
    size_t rlen;
    unsigned long long mlen;
    unsigned char tag = 0;
    int eof;
    int saw_final = 0;
    int rc = SXT_OK;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (keylen != (int)crypto_secretstream_xchacha20poly1305_KEYBYTES) {
        set_error("sxt_decrypt_file: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (src_path == NULL || dst_path == NULL || key == NULL) {
        set_error("sxt_decrypt_file: null path or key");
        return SXT_ERR_BADARG;
    }
    fsrc = fopen(src_path, "rb");
    if (fsrc == NULL) {
        set_error("sxt_decrypt_file: cannot open source file");
        return SXT_ERR_IO;
    }
    fdst = fopen(dst_path, "wb");
    if (fdst == NULL) {
        fclose(fsrc);
        set_error("sxt_decrypt_file: cannot open destination file");
        return SXT_ERR_IO;
    }

    if (fread(header, 1, sizeof(header), fsrc) != sizeof(header)) {
        /* too short even to hold the stream header: corrupt or truncated. */
        set_error("sxt_decrypt_file: file is not a valid stream (no header)");
        rc = SXT_ERR_AUTH;
    } else if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        set_error("sxt_decrypt_file: malformed stream header");
        rc = SXT_ERR_AUTH;
    } else {
        do {
            rlen = fread(in, 1, sizeof(in), fsrc);
            if (ferror(fsrc)) {
                set_error("sxt_decrypt_file: read error");
                rc = SXT_ERR_IO;
                break;
            }
            eof = feof(fsrc);
            if (rlen < (size_t)ab) {
                /* a valid chunk is at least ABYTES (the final 0-length chunk is
                 * still ABYTES); anything shorter means truncation/corruption. */
                set_error("sxt_decrypt_file: truncated or corrupt stream");
                rc = SXT_ERR_AUTH;
                break;
            }
            if (crypto_secretstream_xchacha20poly1305_pull(&st, out, &mlen, &tag,
                                                           in, (unsigned long long)rlen,
                                                           NULL, 0) != 0) {
                set_error("sxt_decrypt_file: wrong key or tampered data");
                rc = SXT_ERR_AUTH;
                break;
            }
            if (fwrite(out, 1, (size_t)mlen, fdst) != (size_t)mlen) {
                set_error("sxt_decrypt_file: write error");
                rc = SXT_ERR_IO;
                break;
            }
            if (tag == (unsigned char)crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
                saw_final = 1;
                break;                   /* clean end of stream */
            }
            if (eof) {
                /* reached EOF without the FINAL tag: the stream was truncated. */
                set_error("sxt_decrypt_file: stream truncated before its final chunk");
                rc = SXT_ERR_AUTH;
                break;
            }
        } while (!eof);
        if (rc == SXT_OK && !saw_final) {
            set_error("sxt_decrypt_file: stream ended without a final chunk");
            rc = SXT_ERR_AUTH;
        }
    }

    sodium_memzero(&st, sizeof(st));
    sodium_memzero(in, sizeof(in));
    sodium_memzero(out, sizeof(out));
    if (fclose(fdst) != 0 && rc == SXT_OK) {
        set_error("sxt_decrypt_file: close error");
        rc = SXT_ERR_IO;
    }
    fclose(fsrc);
    if (rc != SXT_OK) {
        remove(dst_path);                /* never leave a partial plaintext */
    }
    return rc;
}

/* ========================================================================== *
 * Phase 4: public-key boxes (X25519) + signatures (ed25519).
 * ========================================================================== */

SXT_API int SXT_CALL sxt_box_publickeybytes(void) { return (int)crypto_box_PUBLICKEYBYTES; }
SXT_API int SXT_CALL sxt_box_secretkeybytes(void) { return (int)crypto_box_SECRETKEYBYTES; }
SXT_API int SXT_CALL sxt_box_noncebytes(void)     { return (int)crypto_box_NONCEBYTES; }
SXT_API int SXT_CALL sxt_box_macbytes(void)       { return (int)crypto_box_MACBYTES; }
SXT_API int SXT_CALL sxt_box_sealbytes(void)      { return (int)crypto_box_SEALBYTES; }
SXT_API int SXT_CALL sxt_box_seedbytes(void)      { return (int)crypto_box_SEEDBYTES; }

SXT_API int SXT_CALL sxt_box_keypair(unsigned char *pk_out, int pk_cap,
                                     unsigned char *sk_out, int sk_cap)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (pk_cap < (int)crypto_box_PUBLICKEYBYTES || sk_cap < (int)crypto_box_SECRETKEYBYTES) {
        set_error("sxt_box_keypair: output buffer too small");
        return SXT_ERR_BADARG;
    }
    if (pk_out == NULL || sk_out == NULL) {
        set_error("sxt_box_keypair: null buffer");
        return SXT_ERR_BADARG;
    }
    crypto_box_keypair(pk_out, sk_out);
    return SXT_OK;
}

SXT_API int SXT_CALL sxt_box_keypair_from_seed(unsigned char *pk_out, int pk_cap,
                                               unsigned char *sk_out, int sk_cap,
                                               const unsigned char *seed, int seedlen)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (seedlen != (int)crypto_box_SEEDBYTES) {
        set_error("sxt_box_keypair_from_seed: wrong seed length");
        return SXT_ERR_BADARG;
    }
    if (pk_cap < (int)crypto_box_PUBLICKEYBYTES || sk_cap < (int)crypto_box_SECRETKEYBYTES) {
        set_error("sxt_box_keypair_from_seed: output buffer too small");
        return SXT_ERR_BADARG;
    }
    if (pk_out == NULL || sk_out == NULL || seed == NULL) {
        set_error("sxt_box_keypair_from_seed: null buffer");
        return SXT_ERR_BADARG;
    }
    crypto_box_seed_keypair(pk_out, sk_out, seed);
    return SXT_OK;
}

SXT_API int SXT_CALL sxt_box(unsigned char *out, int cap,
                             const unsigned char *msg, int msglen,
                             const unsigned char *recipient_pk, int pklen,
                             const unsigned char *sender_sk, int sklen)
{
    const int noncebytes = (int)crypto_box_NONCEBYTES;
    const int macbytes = (int)crypto_box_MACBYTES;
    int needed;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (msglen < 0) {
        set_error("sxt_box: negative length");
        return SXT_ERR_BADARG;
    }
    if (pklen != (int)crypto_box_PUBLICKEYBYTES || sklen != (int)crypto_box_SECRETKEYBYTES) {
        set_error("sxt_box: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (msglen >= SXT_MAX_BUFFER - noncebytes - macbytes) {
        set_error("sxt_box: message too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    needed = noncebytes + msglen + macbytes;
    if (cap < needed) {
        return -needed;
    }
    if (out == NULL || recipient_pk == NULL || sender_sk == NULL) {
        set_error("sxt_box: null buffer");
        return SXT_ERR_BADARG;
    }
    if (msglen > 0 && msg == NULL) {
        set_error("sxt_box: null message");
        return SXT_ERR_BADARG;
    }
    randombytes_buf(out, (size_t)noncebytes);
    if (crypto_box_easy(out + noncebytes, msg, (unsigned long long)msglen,
                        out, recipient_pk, sender_sk) != 0) {
        set_error("sxt_box: encryption failed");
        return SXT_ERR_BADARG;
    }
    return needed;
}

SXT_API int SXT_CALL sxt_box_open(unsigned char *out, int cap,
                                  const unsigned char *box, int boxlen,
                                  const unsigned char *sender_pk, int pklen,
                                  const unsigned char *recipient_sk, int sklen)
{
    const int noncebytes = (int)crypto_box_NONCEBYTES;
    const int macbytes = (int)crypto_box_MACBYTES;
    int plainlen;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (pklen != (int)crypto_box_PUBLICKEYBYTES || sklen != (int)crypto_box_SECRETKEYBYTES) {
        set_error("sxt_box_open: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (boxlen < noncebytes + macbytes) {
        set_error("sxt_box_open: ciphertext too short");
        return SXT_ERR_BADARG;
    }
    if (boxlen >= SXT_MAX_BUFFER) {   /* keep -plainlen inside the -needed band */
        set_error("sxt_box_open: ciphertext too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    plainlen = boxlen - noncebytes - macbytes;
    if (cap < plainlen) {
        return -plainlen;
    }
    if (box == NULL || sender_pk == NULL || recipient_sk == NULL) {
        set_error("sxt_box_open: null buffer");
        return SXT_ERR_BADARG;
    }
    if (plainlen > 0 && out == NULL) {
        set_error("sxt_box_open: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (crypto_box_open_easy(out, box + noncebytes,
                             (unsigned long long)(boxlen - noncebytes),
                             box, sender_pk, recipient_sk) != 0) {
        set_error("sxt_box_open: wrong key or tampered data");
        return SXT_ERR_AUTH;
    }
    return plainlen;
}

SXT_API int SXT_CALL sxt_box_seal(unsigned char *out, int cap,
                                  const unsigned char *msg, int msglen,
                                  const unsigned char *recipient_pk, int pklen)
{
    const int sealbytes = (int)crypto_box_SEALBYTES;
    int needed;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (msglen < 0) {
        set_error("sxt_box_seal: negative length");
        return SXT_ERR_BADARG;
    }
    if (pklen != (int)crypto_box_PUBLICKEYBYTES) {
        set_error("sxt_box_seal: wrong public key length");
        return SXT_ERR_BADARG;
    }
    if (msglen >= SXT_MAX_BUFFER - sealbytes) {
        set_error("sxt_box_seal: message too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    needed = msglen + sealbytes;
    if (cap < needed) {
        return -needed;
    }
    if (out == NULL || recipient_pk == NULL) {
        set_error("sxt_box_seal: null buffer");
        return SXT_ERR_BADARG;
    }
    if (msglen > 0 && msg == NULL) {
        set_error("sxt_box_seal: null message");
        return SXT_ERR_BADARG;
    }
    if (crypto_box_seal(out, msg, (unsigned long long)msglen, recipient_pk) != 0) {
        set_error("sxt_box_seal: sealing failed");
        return SXT_ERR_BADARG;
    }
    return needed;
}

SXT_API int SXT_CALL sxt_box_seal_open(unsigned char *out, int cap,
                                       const unsigned char *sealed, int sealedlen,
                                       const unsigned char *recipient_pk, int pklen,
                                       const unsigned char *recipient_sk, int sklen)
{
    const int sealbytes = (int)crypto_box_SEALBYTES;
    int plainlen;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (pklen != (int)crypto_box_PUBLICKEYBYTES || sklen != (int)crypto_box_SECRETKEYBYTES) {
        set_error("sxt_box_seal_open: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (sealedlen < sealbytes) {
        set_error("sxt_box_seal_open: sealed box too short");
        return SXT_ERR_BADARG;
    }
    if (sealedlen >= SXT_MAX_BUFFER) {   /* keep -plainlen inside the -needed band */
        set_error("sxt_box_seal_open: sealed box too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    plainlen = sealedlen - sealbytes;
    if (cap < plainlen) {
        return -plainlen;
    }
    if (sealed == NULL || recipient_pk == NULL || recipient_sk == NULL) {
        set_error("sxt_box_seal_open: null buffer");
        return SXT_ERR_BADARG;
    }
    if (plainlen > 0 && out == NULL) {
        set_error("sxt_box_seal_open: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (crypto_box_seal_open(out, sealed, (unsigned long long)sealedlen,
                             recipient_pk, recipient_sk) != 0) {
        set_error("sxt_box_seal_open: wrong key or tampered data");
        return SXT_ERR_AUTH;
    }
    return plainlen;
}

/* ---- ed25519 signatures ------------------------------------------------- */

SXT_API int SXT_CALL sxt_sign_publickeybytes(void) { return (int)crypto_sign_PUBLICKEYBYTES; }
SXT_API int SXT_CALL sxt_sign_secretkeybytes(void) { return (int)crypto_sign_SECRETKEYBYTES; }
SXT_API int SXT_CALL sxt_sign_bytes(void)          { return (int)crypto_sign_BYTES; }
SXT_API int SXT_CALL sxt_sign_seedbytes(void)      { return (int)crypto_sign_SEEDBYTES; }

SXT_API int SXT_CALL sxt_sign_keypair(unsigned char *pk_out, int pk_cap,
                                      unsigned char *sk_out, int sk_cap)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (pk_cap < (int)crypto_sign_PUBLICKEYBYTES || sk_cap < (int)crypto_sign_SECRETKEYBYTES) {
        set_error("sxt_sign_keypair: output buffer too small");
        return SXT_ERR_BADARG;
    }
    if (pk_out == NULL || sk_out == NULL) {
        set_error("sxt_sign_keypair: null buffer");
        return SXT_ERR_BADARG;
    }
    crypto_sign_keypair(pk_out, sk_out);
    return SXT_OK;
}

SXT_API int SXT_CALL sxt_sign_keypair_from_seed(unsigned char *pk_out, int pk_cap,
                                                unsigned char *sk_out, int sk_cap,
                                                const unsigned char *seed, int seedlen)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (seedlen != (int)crypto_sign_SEEDBYTES) {
        set_error("sxt_sign_keypair_from_seed: wrong seed length");
        return SXT_ERR_BADARG;
    }
    if (pk_cap < (int)crypto_sign_PUBLICKEYBYTES || sk_cap < (int)crypto_sign_SECRETKEYBYTES) {
        set_error("sxt_sign_keypair_from_seed: output buffer too small");
        return SXT_ERR_BADARG;
    }
    if (pk_out == NULL || sk_out == NULL || seed == NULL) {
        set_error("sxt_sign_keypair_from_seed: null buffer");
        return SXT_ERR_BADARG;
    }
    crypto_sign_seed_keypair(pk_out, sk_out, seed);
    return SXT_OK;
}

SXT_API int SXT_CALL sxt_sign_detached(unsigned char *sig_out, int sig_cap,
                                       const unsigned char *msg, int msglen,
                                       const unsigned char *sk, int sklen)
{
    const int sigbytes = (int)crypto_sign_BYTES;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (msglen < 0) {
        set_error("sxt_sign_detached: negative length");
        return SXT_ERR_BADARG;
    }
    if (sklen != (int)crypto_sign_SECRETKEYBYTES) {
        set_error("sxt_sign_detached: wrong secret key length");
        return SXT_ERR_BADARG;
    }
    if (sig_cap < sigbytes) {
        return -sigbytes;
    }
    if (sig_out == NULL || sk == NULL) {
        set_error("sxt_sign_detached: null buffer");
        return SXT_ERR_BADARG;
    }
    if (msglen > 0 && msg == NULL) {
        set_error("sxt_sign_detached: null message");
        return SXT_ERR_BADARG;
    }
    if (crypto_sign_detached(sig_out, NULL, msg, (unsigned long long)msglen, sk) != 0) {
        set_error("sxt_sign_detached: signing failed");
        return SXT_ERR_BADARG;
    }
    return sigbytes;
}

SXT_API int SXT_CALL sxt_sign_verify_detached(const unsigned char *sig, int siglen,
                                              const unsigned char *msg, int msglen,
                                              const unsigned char *pk, int pklen)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return 0;
    }
    /* Any malformed input cannot be a valid signature, so it is a clean 0, never
     * an error in the band. */
    if (siglen != (int)crypto_sign_BYTES || pklen != (int)crypto_sign_PUBLICKEYBYTES) {
        return 0;
    }
    if (msglen < 0 || sig == NULL || pk == NULL || (msglen > 0 && msg == NULL)) {
        return 0;
    }
    return crypto_sign_verify_detached(sig, msg, (unsigned long long)msglen, pk) == 0 ? 1 : 0;
}

SXT_API int SXT_CALL sxt_sign(unsigned char *out, int cap,
                              const unsigned char *msg, int msglen,
                              const unsigned char *sk, int sklen)
{
    const int sigbytes = (int)crypto_sign_BYTES;
    int needed;
    unsigned long long slen = 0;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (msglen < 0) {
        set_error("sxt_sign: negative length");
        return SXT_ERR_BADARG;
    }
    if (sklen != (int)crypto_sign_SECRETKEYBYTES) {
        set_error("sxt_sign: wrong secret key length");
        return SXT_ERR_BADARG;
    }
    if (msglen >= SXT_MAX_BUFFER - sigbytes) {
        set_error("sxt_sign: message too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    needed = sigbytes + msglen;
    if (cap < needed) {
        return -needed;
    }
    if (out == NULL || sk == NULL) {
        set_error("sxt_sign: null buffer");
        return SXT_ERR_BADARG;
    }
    if (msglen > 0 && msg == NULL) {
        set_error("sxt_sign: null message");
        return SXT_ERR_BADARG;
    }
    if (crypto_sign(out, &slen, msg, (unsigned long long)msglen, sk) != 0) {
        set_error("sxt_sign: signing failed");
        return SXT_ERR_BADARG;
    }
    return (int)slen;
}

SXT_API int SXT_CALL sxt_sign_open(unsigned char *out, int cap,
                                   const unsigned char *signed_msg, int signedlen,
                                   const unsigned char *pk, int pklen)
{
    const int sigbytes = (int)crypto_sign_BYTES;
    int maxmsg;
    unsigned long long mlen = 0;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (pklen != (int)crypto_sign_PUBLICKEYBYTES) {
        set_error("sxt_sign_open: wrong public key length");
        return SXT_ERR_BADARG;
    }
    if (signedlen < sigbytes) {
        set_error("sxt_sign_open: signed message too short");
        return SXT_ERR_BADARG;
    }
    if (signedlen >= SXT_MAX_BUFFER) {   /* keep -maxmsg inside the -needed band */
        set_error("sxt_sign_open: signed message too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    maxmsg = signedlen - sigbytes;
    if (cap < maxmsg) {
        return -maxmsg;
    }
    if (signed_msg == NULL || pk == NULL) {
        set_error("sxt_sign_open: null buffer");
        return SXT_ERR_BADARG;
    }
    if (maxmsg > 0 && out == NULL) {
        set_error("sxt_sign_open: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (crypto_sign_open(out, &mlen, signed_msg, (unsigned long long)signedlen, pk) != 0) {
        set_error("sxt_sign_open: bad signature");
        return SXT_ERR_AUTH;
    }
    return (int)mlen;
}

/* ========================================================================== *
 * Phase 5: key derivation (kdf), key exchange (kx), padding.
 * ========================================================================== */

SXT_API int SXT_CALL sxt_kdf_keybytes(void)     { return (int)crypto_kdf_KEYBYTES; }
SXT_API int SXT_CALL sxt_kdf_contextbytes(void) { return (int)crypto_kdf_CONTEXTBYTES; }
SXT_API int SXT_CALL sxt_kdf_bytes_min(void)    { return (int)crypto_kdf_BYTES_MIN; }
SXT_API int SXT_CALL sxt_kdf_bytes_max(void)    { return (int)crypto_kdf_BYTES_MAX; }

SXT_API int SXT_CALL sxt_kdf_derive(unsigned char *out, int cap, int subkeylen,
                                    const char *subkey_id,
                                    const unsigned char *context, int contextlen,
                                    const unsigned char *masterkey, int masterkeylen)
{
    unsigned long long id = 0;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (subkeylen < (int)crypto_kdf_BYTES_MIN || subkeylen > (int)crypto_kdf_BYTES_MAX) {
        set_error("sxt_kdf_derive: subkey length out of range");
        return SXT_ERR_BADARG;
    }
    if (contextlen != (int)crypto_kdf_CONTEXTBYTES) {
        set_error("sxt_kdf_derive: wrong context length");
        return SXT_ERR_BADARG;
    }
    if (masterkeylen != (int)crypto_kdf_KEYBYTES) {
        set_error("sxt_kdf_derive: wrong master key length");
        return SXT_ERR_BADARG;
    }
    if (parse_u64(subkey_id, &id) != 0) {
        set_error("sxt_kdf_derive: subkey id is not a valid decimal number");
        return SXT_ERR_BADARG;
    }
    if (cap < subkeylen) {
        return -subkeylen;
    }
    if (out == NULL || context == NULL || masterkey == NULL) {
        set_error("sxt_kdf_derive: null buffer");
        return SXT_ERR_BADARG;
    }
    if (crypto_kdf_derive_from_key(out, (size_t)subkeylen, id,
                                   (const char *)context, masterkey) != 0) {
        set_error("sxt_kdf_derive: derivation failed");
        return SXT_ERR_BADARG;
    }
    return subkeylen;
}

SXT_API int SXT_CALL sxt_kx_publickeybytes(void)  { return (int)crypto_kx_PUBLICKEYBYTES; }
SXT_API int SXT_CALL sxt_kx_secretkeybytes(void)  { return (int)crypto_kx_SECRETKEYBYTES; }
SXT_API int SXT_CALL sxt_kx_sessionkeybytes(void) { return (int)crypto_kx_SESSIONKEYBYTES; }
SXT_API int SXT_CALL sxt_kx_seedbytes(void)       { return (int)crypto_kx_SEEDBYTES; }

SXT_API int SXT_CALL sxt_kx_keypair(unsigned char *pk_out, int pk_cap,
                                    unsigned char *sk_out, int sk_cap)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (pk_cap < (int)crypto_kx_PUBLICKEYBYTES || sk_cap < (int)crypto_kx_SECRETKEYBYTES) {
        set_error("sxt_kx_keypair: output buffer too small");
        return SXT_ERR_BADARG;
    }
    if (pk_out == NULL || sk_out == NULL) {
        set_error("sxt_kx_keypair: null buffer");
        return SXT_ERR_BADARG;
    }
    crypto_kx_keypair(pk_out, sk_out);
    return SXT_OK;
}

SXT_API int SXT_CALL sxt_kx_keypair_from_seed(unsigned char *pk_out, int pk_cap,
                                              unsigned char *sk_out, int sk_cap,
                                              const unsigned char *seed, int seedlen)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (seedlen != (int)crypto_kx_SEEDBYTES) {
        set_error("sxt_kx_keypair_from_seed: wrong seed length");
        return SXT_ERR_BADARG;
    }
    if (pk_cap < (int)crypto_kx_PUBLICKEYBYTES || sk_cap < (int)crypto_kx_SECRETKEYBYTES) {
        set_error("sxt_kx_keypair_from_seed: output buffer too small");
        return SXT_ERR_BADARG;
    }
    if (pk_out == NULL || sk_out == NULL || seed == NULL) {
        set_error("sxt_kx_keypair_from_seed: null buffer");
        return SXT_ERR_BADARG;
    }
    crypto_kx_seed_keypair(pk_out, sk_out, seed);
    return SXT_OK;
}

SXT_API int SXT_CALL sxt_kx_client_session_keys(unsigned char *rx_out, int rx_cap,
                                                unsigned char *tx_out, int tx_cap,
                                                const unsigned char *client_pk, int client_pklen,
                                                const unsigned char *client_sk, int client_sklen,
                                                const unsigned char *server_pk, int server_pklen)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (rx_cap < (int)crypto_kx_SESSIONKEYBYTES || tx_cap < (int)crypto_kx_SESSIONKEYBYTES) {
        set_error("sxt_kx_client_session_keys: output buffer too small");
        return SXT_ERR_BADARG;
    }
    if (client_pklen != (int)crypto_kx_PUBLICKEYBYTES ||
        client_sklen != (int)crypto_kx_SECRETKEYBYTES ||
        server_pklen != (int)crypto_kx_PUBLICKEYBYTES) {
        set_error("sxt_kx_client_session_keys: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (rx_out == NULL || tx_out == NULL ||
        client_pk == NULL || client_sk == NULL || server_pk == NULL) {
        set_error("sxt_kx_client_session_keys: null buffer");
        return SXT_ERR_BADARG;
    }
    /* Returns -1 if the server's public key is unacceptable. */
    if (crypto_kx_client_session_keys(rx_out, tx_out, client_pk, client_sk, server_pk) != 0) {
        set_error("sxt_kx_client_session_keys: peer public key rejected");
        return SXT_ERR_AUTH;
    }
    return SXT_OK;
}

SXT_API int SXT_CALL sxt_kx_server_session_keys(unsigned char *rx_out, int rx_cap,
                                                unsigned char *tx_out, int tx_cap,
                                                const unsigned char *server_pk, int server_pklen,
                                                const unsigned char *server_sk, int server_sklen,
                                                const unsigned char *client_pk, int client_pklen)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (rx_cap < (int)crypto_kx_SESSIONKEYBYTES || tx_cap < (int)crypto_kx_SESSIONKEYBYTES) {
        set_error("sxt_kx_server_session_keys: output buffer too small");
        return SXT_ERR_BADARG;
    }
    if (server_pklen != (int)crypto_kx_PUBLICKEYBYTES ||
        server_sklen != (int)crypto_kx_SECRETKEYBYTES ||
        client_pklen != (int)crypto_kx_PUBLICKEYBYTES) {
        set_error("sxt_kx_server_session_keys: wrong key length");
        return SXT_ERR_BADARG;
    }
    if (rx_out == NULL || tx_out == NULL ||
        server_pk == NULL || server_sk == NULL || client_pk == NULL) {
        set_error("sxt_kx_server_session_keys: null buffer");
        return SXT_ERR_BADARG;
    }
    if (crypto_kx_server_session_keys(rx_out, tx_out, server_pk, server_sk, client_pk) != 0) {
        set_error("sxt_kx_server_session_keys: peer public key rejected");
        return SXT_ERR_AUTH;
    }
    return SXT_OK;
}

SXT_API int SXT_CALL sxt_pad(unsigned char *out, int cap,
                             const unsigned char *in, int inlen, int blocksize)
{
    size_t padded_len = 0;
    int needed;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (inlen < 0 || blocksize <= 0) {
        set_error("sxt_pad: bad length or block size");
        return SXT_ERR_BADARG;
    }
    /* sodium_pad always adds 1..blocksize bytes, rounding up to a multiple. */
    if (inlen / blocksize >= (SXT_MAX_BUFFER / blocksize) - 1) {
        set_error("sxt_pad: result too large for a single buffer");
        return SXT_ERR_BADARG;
    }
    needed = (inlen / blocksize + 1) * blocksize;
    if (cap < needed) {
        return -needed;
    }
    if (out == NULL || (inlen > 0 && in == NULL)) {
        set_error("sxt_pad: null buffer");
        return SXT_ERR_BADARG;
    }
    /* Place the data, then pad it in place inside the caller's block. */
    if (inlen > 0) {
        memcpy(out, in, (size_t)inlen);
    }
    if (sodium_pad(&padded_len, out, (size_t)inlen, (size_t)blocksize, (size_t)cap) != 0) {
        set_error("sxt_pad: padding failed");
        return SXT_ERR_BADARG;
    }
    return (int)padded_len;
}

SXT_API int SXT_CALL sxt_unpad(const unsigned char *in, int inlen, int blocksize)
{
    size_t unpadded_len = 0;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (inlen < 0 || blocksize <= 0) {
        set_error("sxt_unpad: bad length or block size");
        return SXT_ERR_BADARG;
    }
    if (inlen > 0 && in == NULL) {
        set_error("sxt_unpad: null buffer");
        return SXT_ERR_BADARG;
    }
    if (sodium_unpad(&unpadded_len, in, (size_t)inlen, (size_t)blocksize) != 0) {
        set_error("sxt_unpad: malformed padding");
        return SXT_ERR_ENCODING;
    }
    return (int)unpadded_len;
}

/* ===========================================================================
 * Phase 6: streaming / whole-file BLAKE2b, and an unbiased random integer.
 *
 * sxHash takes a whole Data; this adds the complement for data that should not
 * be fully resident: a C-side file hash (the bytes never enter a Data, just
 * like sxt_encrypt_file) and a multipart init/update/final the script can feed
 * incrementally. randombytes_uniform is a small, safe convenience.
 * =========================================================================== */

/* Uniform random integer in [0, upper_bound). Unbiased (rejection sampling
 * inside libsodium), unlike `random() mod n`. upper_bound is capped at
 * SXT_MAX_BUFFER so the result is always a non-negative int below the error
 * band. */
SXT_API int SXT_CALL sxt_randombytes_uniform(int upper_bound)
{
    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (upper_bound < 1 || upper_bound > SXT_MAX_BUFFER) {
        set_error("sxt_randombytes_uniform: upper_bound must be in [1, SXT_MAX_BUFFER]");
        return SXT_ERR_BADARG;
    }
    return (int)randombytes_uniform((uint32_t)upper_bound);
}

/* ---------------------------------------------------------------------------
 * Multipart hash handle table. SAME generation-tagged scheme as s_streams, but
 * a SEPARATE table so the proven secretstream code is untouched. Hash handles
 * set bit 15 of the low word (SXT_HASH_TAG); that puts their decoded "slot
 * index" (>= 0x8000) out of the stream table's 0..63 range, so a hash handle
 * accidentally passed to stream_lookup / sxt_free_stream is rejected as
 * out-of-range with no change to that code, and a stream handle passed here is
 * rejected because it lacks the tag. Handles stay positive and below the error
 * band (max ~0x3FFF8020).
 * --------------------------------------------------------------------------- */
#define SXT_HASH_SLOTS 32
#define SXT_HASH_TAG   0x8000

typedef struct {
    int in_use;
    int gen;        /* current generation; starts at 1, bumped on free */
    int outlen;     /* digest length captured at init, produced by final */
    crypto_generichash_state state;
} sxt_hash_slot;

static sxt_hash_slot s_hashes[SXT_HASH_SLOTS];

static int hash_make_handle(int idx, int gen)
{
    return ((gen & 0x3FFF) << 16) | SXT_HASH_TAG | ((idx + 1) & 0x7FFF);
}

static sxt_hash_slot *hash_lookup(int handle)
{
    int idx, gen;
    if ((handle & SXT_HASH_TAG) == 0) {
        return NULL;                 /* not a hash handle (e.g. a stream handle) */
    }
    idx = (handle & 0x7FFF) - 1;
    gen = (handle >> 16) & 0x3FFF;
    if (idx < 0 || idx >= SXT_HASH_SLOTS) {
        return NULL;
    }
    if (!s_hashes[idx].in_use || s_hashes[idx].gen != gen) {
        return NULL;                 /* stale or recycled handle */
    }
    return &s_hashes[idx];
}

static int hash_alloc(void)
{
    int i;
    for (i = 0; i < SXT_HASH_SLOTS; i++) {
        if (!s_hashes[i].in_use) {
            if (s_hashes[i].gen <= 0) {
                s_hashes[i].gen = 1;
            }
            s_hashes[i].in_use = 1;
            return hash_make_handle(i, s_hashes[i].gen);
        }
    }
    return 0;                        /* table full */
}

SXT_API void SXT_CALL sxt_hash_free(int handle)
{
    sxt_hash_slot *slot = hash_lookup(handle);
    int idx;
    if (slot == NULL) {
        return;                      /* unknown / already-freed: idempotent no-op */
    }
    idx = (handle & 0x7FFF) - 1;
    sodium_memzero(&s_hashes[idx].state, sizeof(s_hashes[idx].state));
    s_hashes[idx].in_use = 0;
    s_hashes[idx].outlen = 0;
    s_hashes[idx].gen++;             /* invalidate every outstanding handle */
    if (s_hashes[idx].gen > 0x3FFF) {
        s_hashes[idx].gen = 1;       /* wrap, staying positive */
    }
}

/* Validate an (optional) key + a digest length against BLAKE2b's bounds. */
static int hash_check_params(const unsigned char *key, int keylen, int outlen,
                             const char *who)
{
    if (outlen < (int)crypto_generichash_BYTES_MIN ||
        outlen > (int)crypto_generichash_BYTES_MAX) {
        set_error(who);              /* caller passes the specific message */
        return SXT_ERR_BADARG;
    }
    if (keylen < 0 || keylen > (int)crypto_generichash_KEYBYTES_MAX) {
        set_error(who);
        return SXT_ERR_BADARG;
    }
    if (keylen > 0 && key == NULL) {
        set_error(who);
        return SXT_ERR_BADARG;
    }
    return SXT_OK;
}

SXT_API int SXT_CALL sxt_hash_init(const unsigned char *key, int keylen, int outlen)
{
    int handle;
    sxt_hash_slot *slot;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (hash_check_params(key, keylen, outlen,
                          "sxt_hash_init: bad key length or digest length") != SXT_OK) {
        return SXT_ERR_BADARG;
    }
    handle = hash_alloc();
    if (handle == 0) {
        set_error("sxt_hash_init: too many open hash states");
        return SXT_ERR_BADHANDLE;
    }
    slot = hash_lookup(handle);
    if (slot == NULL ||
        crypto_generichash_init(&slot->state, (keylen > 0 ? key : NULL),
                                (size_t)keylen, (size_t)outlen) != 0) {
        sxt_hash_free(handle);
        set_error("sxt_hash_init: init failed");
        return SXT_ERR_BADARG;
    }
    slot->outlen = outlen;
    return handle;
}

SXT_API int SXT_CALL sxt_hash_update(int handle, const unsigned char *in, int inlen)
{
    sxt_hash_slot *slot;

    clear_error();
    if (inlen < 0) {
        set_error("sxt_hash_update: negative length");
        return SXT_ERR_BADARG;
    }
    slot = hash_lookup(handle);
    if (slot == NULL) {
        set_error("sxt_hash_update: bad or spent handle");
        return SXT_ERR_BADHANDLE;
    }
    if (inlen > 0 && in == NULL) {
        set_error("sxt_hash_update: null input");
        return SXT_ERR_BADARG;
    }
    if (inlen > 0 &&
        crypto_generichash_update(&slot->state, in, (unsigned long long)inlen) != 0) {
        set_error("sxt_hash_update: update failed");
        return SXT_ERR_BADARG;
    }
    return SXT_OK;
}

SXT_API int SXT_CALL sxt_hash_final(int handle, unsigned char *out, int cap)
{
    sxt_hash_slot *slot;
    int outlen;

    clear_error();
    slot = hash_lookup(handle);
    if (slot == NULL) {
        set_error("sxt_hash_final: bad or spent handle");
        return SXT_ERR_BADHANDLE;
    }
    outlen = slot->outlen;
    /* Size check BEFORE the consuming final call: a short buffer is a -needed
     * with the state still intact, so the caller can retry. */
    if (cap < outlen) {
        return -outlen;
    }
    if (out == NULL) {
        set_error("sxt_hash_final: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (crypto_generichash_final(&slot->state, out, (size_t)outlen) != 0) {
        sxt_hash_free(handle);
        set_error("sxt_hash_final: finalization failed");
        return SXT_ERR_BADARG;
    }
    sxt_hash_free(handle);           /* state is consumed; release the slot */
    return outlen;
}

SXT_API int SXT_CALL sxt_hash_file(const char *path, unsigned char *out, int cap, int outlen,
                                   const unsigned char *key, int keylen)
{
    crypto_generichash_state st;
    unsigned char buf[SXT_FILE_CHUNK];
    FILE *f;
    size_t rlen;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (hash_check_params(key, keylen, outlen,
                          "sxt_hash_file: bad key length or digest length") != SXT_OK) {
        return SXT_ERR_BADARG;
    }
    if (path == NULL) {
        set_error("sxt_hash_file: null path");
        return SXT_ERR_BADARG;
    }
    if (cap < outlen) {
        return -outlen;              /* size query; nothing read or written */
    }
    if (out == NULL) {
        set_error("sxt_hash_file: null output buffer");
        return SXT_ERR_BADARG;
    }
    f = fopen(path, "rb");
    if (f == NULL) {
        set_error("sxt_hash_file: cannot open file");
        return SXT_ERR_IO;
    }
    if (crypto_generichash_init(&st, (keylen > 0 ? key : NULL),
                                (size_t)keylen, (size_t)outlen) != 0) {
        fclose(f);
        set_error("sxt_hash_file: init failed");
        return SXT_ERR_BADARG;
    }
    do {
        rlen = fread(buf, 1, sizeof(buf), f);
        if (ferror(f)) {
            fclose(f);
            sodium_memzero(&st, sizeof(st));
            set_error("sxt_hash_file: read error");
            return SXT_ERR_IO;
        }
        if (rlen > 0) {
            crypto_generichash_update(&st, buf, (unsigned long long)rlen);
        }
    } while (!feof(f));
    fclose(f);
    sodium_memzero(buf, sizeof(buf));
    crypto_generichash_final(&st, out, (size_t)outlen);
    return outlen;
}

/* --- ABI 6: ed25519 key expansion + HMAC-SHA256 --------------------------- */

SXT_API int SXT_CALL sxt_sign_expandedkeybytes(void) { return (int)crypto_hash_sha512_BYTES; }

SXT_API int SXT_CALL sxt_sign_seed_to_expanded_key(unsigned char *out, int cap,
                                                   const unsigned char *seed, int seedlen)
{
    unsigned char h[crypto_hash_sha512_BYTES];   /* == the 64-byte expanded key after the clamp */

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (seedlen != (int)crypto_sign_SEEDBYTES) {
        set_error("sxt_sign_seed_to_expanded_key: wrong seed length");
        return SXT_ERR_BADARG;
    }
    if (cap < (int)crypto_hash_sha512_BYTES) {
        return -(int)crypto_hash_sha512_BYTES;
    }
    if (out == NULL || seed == NULL) {
        set_error("sxt_sign_seed_to_expanded_key: null buffer");
        return SXT_ERR_BADARG;
    }
    /* The ed25519 private scalar a and nonce prefix RH are SHA-512(seed) split in
     * half, with the low half clamped onto the curve. This (a || RH) is exactly
     * what a Tor v3 onion service stores as its expanded secret key; we add no
     * crypto of our own, only crypto_hash_sha512 plus the standard clamp. */
    crypto_hash_sha512(h, seed, (unsigned long long)crypto_sign_SEEDBYTES);
    h[0]  &= 248;
    h[31] &= 127;
    h[31] |= 64;
    memcpy(out, h, sizeof h);
    sodium_memzero(h, sizeof h);
    return (int)crypto_hash_sha512_BYTES;
}

SXT_API int SXT_CALL sxt_hmac_sha256_bytes(void) { return (int)crypto_auth_hmacsha256_BYTES; }

SXT_API int SXT_CALL sxt_hmac_sha256(unsigned char *out, int cap,
                                     const unsigned char *key, int keylen,
                                     const unsigned char *msg, int msglen)
{
    crypto_auth_hmacsha256_state st;
    const int outbytes = (int)crypto_auth_hmacsha256_BYTES;

    clear_error();
    if (ensure_init() != SXT_OK) {
        return SXT_ERR_INIT;
    }
    if (keylen < 0 || msglen < 0) {
        set_error("sxt_hmac_sha256: negative length");
        return SXT_ERR_BADARG;
    }
    if (cap < outbytes) {
        return -outbytes;
    }
    if (out == NULL) {
        set_error("sxt_hmac_sha256: null output buffer");
        return SXT_ERR_BADARG;
    }
    if (keylen > 0 && key == NULL) {
        set_error("sxt_hmac_sha256: null key");
        return SXT_ERR_BADARG;
    }
    if (msglen > 0 && msg == NULL) {
        set_error("sxt_hmac_sha256: null message");
        return SXT_ERR_BADARG;
    }
    /* Multipart init takes an arbitrary key length; the one-shot form would fix
     * the key at 32 bytes. Pass a valid non-NULL pointer even when a length is 0
     * (an empty key/message is legal) so we never hand libsodium (NULL, 0). */
    crypto_auth_hmacsha256_init(&st, (keylen > 0 ? key : (const unsigned char *)""),
                                (size_t)keylen);
    crypto_auth_hmacsha256_update(&st, (msglen > 0 ? msg : (const unsigned char *)""),
                                  (unsigned long long)msglen);
    crypto_auth_hmacsha256_final(&st, out);
    sodium_memzero(&st, sizeof st);
    return outbytes;
}
