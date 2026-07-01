/*
 * sodium_shim.h - the SodiumXT C ABI (the sxt_* surface).
 *
 * This is the marshaling layer between the LiveCode Builder binding
 * (src/sodium.lcb, public sx*) and libsodium. It adds NO crypto logic of its
 * own: it validates lengths and pointers at the boundary, calls libsodium, and
 * reports bytes-written or a defined error code. See CLAUDE.md ("FFI / C-ABI
 * conventions") and docs/development/implementation-plan.md (section 3) for the
 * full rationale; the operative parts are restated here so a reader of the
 * header alone cannot misuse the contract.
 *
 * Full surface: init/version/randomness; BLAKE2b hashing (one-shot, keyed,
 * multipart, and whole-file) + hex/base64 + constant-time compare; secretbox
 * and AEAD; Argon2id (pwhash / pwhash_str) and the KDF; streaming AEAD
 * (secretstream) and the C-side file helpers; X25519 boxes and sealed boxes;
 * ed25519 signatures; key exchange; and padding. The ABI is versioned by
 * SXT_ABI_VERSION below; bump it on any signature change.
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
#define SXT_ABI_VERSION 5

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
#define SXT_ERR_BASE     (-SXT_MAX_BUFFER)
#define SXT_ERR_INIT     (SXT_ERR_BASE - 1)  /* sodium_init() failed             */
#define SXT_ERR_BADARG   (SXT_ERR_BASE - 2)  /* null pointer / bad length / args */
#define SXT_ERR_AUTH     (SXT_ERR_BASE - 3)  /* tag/signature/verify failed:     */
                                             /* wrong key or tampered data       */
#define SXT_ERR_BADHANDLE (SXT_ERR_BASE - 4) /* stale/unknown stream/hash handle */
#define SXT_ERR_IO       (SXT_ERR_BASE - 5)  /* file open/read/write failed      */
#define SXT_ERR_ENCODING (SXT_ERR_BASE - 6)  /* malformed hex / base64 input     */

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

/*
 * String-returning entry points ALL fill a caller buffer; none returns a
 * `const char *`. This is a hard ABI rule, not a style choice: when the LCB
 * layer bridges a foreign RETURN of ZStringUTF8 / NativeCString / WString, the
 * engine ADOPTS the returned pointer and later calls free() on it (every
 * bridged-C-string foreign type registers free() as its finalizer). Returning
 * a static literal or a library-owned string is therefore free()-on-static:
 * heap corruption on the very first call. So these mirror sxt_bin2hex exactly:
 * the caller passes an out buffer (an MCMemoryAllocate block) plus its
 * capacity, and we return the string length WITHOUT the trailing NUL, or
 * -needed (negative required capacity, NUL included) if the buffer is too
 * small. The engine owns and frees that block; we never hand it our memory.
 */

/* The SodiumXT extension version ("0.1.0"); writes it into out, returns length. */
SXT_API int SXT_CALL sxt_version(char *out, int cap);

/* The linked libsodium version (sodium_version_string()); fills out, returns length. */
SXT_API int SXT_CALL sxt_sodium_version(char *out, int cap);

/* The ABI version compiled into this library (== SXT_ABI_VERSION). */
SXT_API int SXT_CALL sxt_abi_version(void);

/*
 * The last error message on this thread (the empty string when clean) copied
 * into out; returns its length (0 when clean) or -needed. A pure read: it never
 * mutates the thread-local error buffer, so reporting an error cannot clobber
 * the very message being reported.
 */
SXT_API int SXT_CALL sxt_last_error(char *out, int cap);

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

/* --- Phase 1: hashing + encoding + constant-time compare ------------------ */

/*
 * Length constants, exposed as functions so the LCB layer never hardcodes them
 * (libsodium may change them across versions; a hardcoded length is a buffer
 * overflow waiting to happen, CLAUDE.md). All return positive byte counts.
 */
SXT_API int SXT_CALL sxt_hash_bytes(void);          /* default digest size (32)  */
SXT_API int SXT_CALL sxt_hash_bytes_min(void);      /* min digest size (16)      */
SXT_API int SXT_CALL sxt_hash_bytes_max(void);      /* max digest size (64)      */
SXT_API int SXT_CALL sxt_hash_keybytes(void);       /* default key size (32)     */
SXT_API int SXT_CALL sxt_hash_keybytes_min(void);   /* min key size (0 allowed)  */
SXT_API int SXT_CALL sxt_hash_keybytes_max(void);   /* max key size (64)         */

/* base64 variants, mirroring libsodium's sodium_base64_VARIANT_* so the LCB
 * layer passes a name-resolved int rather than a magic number. */
SXT_API int SXT_CALL sxt_base64_variant_original(void);
SXT_API int SXT_CALL sxt_base64_variant_original_no_padding(void);
SXT_API int SXT_CALL sxt_base64_variant_urlsafe(void);
SXT_API int SXT_CALL sxt_base64_variant_urlsafe_no_padding(void);

/*
 * BLAKE2b (crypto_generichash). Writes outlen bytes of digest of in[0..inlen).
 * key is optional: keylen 0 means unkeyed; otherwise keylen must be in
 * [keybytes_min, keybytes_max]. outlen must be in [bytes_min, bytes_max].
 * Returns bytes written (== outlen), -needed, or a hard error.
 */
SXT_API int SXT_CALL sxt_generichash(unsigned char *out, int cap, int outlen,
                                     const unsigned char *in, int inlen,
                                     const unsigned char *key, int keylen);

/*
 * Hex / base64 encode and decode. The encoders report the string length WITHOUT
 * the trailing NUL but require room for it internally (so a -needed reflects the
 * NUL too); the decoders report the decoded byte count. A malformed hex/base64
 * input is SXT_ERR_ENCODING, never a partial/garbage decode.
 */
SXT_API int SXT_CALL sxt_bin2hex(char *out, int cap,
                                 const unsigned char *in, int inlen);
SXT_API int SXT_CALL sxt_hex2bin(unsigned char *out, int cap,
                                 const char *hex, int hexlen);
SXT_API int SXT_CALL sxt_bin2base64(char *out, int cap,
                                    const unsigned char *in, int inlen, int variant);
SXT_API int SXT_CALL sxt_base642bin(unsigned char *out, int cap,
                                    const char *b64, int b64len, int variant);

/*
 * Constant-time equality (sodium_memcmp). Returns 1 if equal, 0 if not. Lengths
 * are not secret, so unequal lengths short-circuit to 0; equal lengths compare
 * in constant time. NEVER compare a secret with the engine `is` / `=` (a timing
 * leak); this is the only sanctioned comparison for MACs, tags, and hashes.
 */
SXT_API int SXT_CALL sxt_memequal(const unsigned char *a, int alen,
                                  const unsigned char *b, int blen);

/* --- Phase 2: secret-key authenticated encryption + Argon2id -------------- */

/* secretbox (XSalsa20-Poly1305) length constants. */
SXT_API int SXT_CALL sxt_secretbox_keybytes(void);
SXT_API int SXT_CALL sxt_secretbox_noncebytes(void);
SXT_API int SXT_CALL sxt_secretbox_macbytes(void);

/*
 * Encrypt msg under key. Output is nonce || ciphertext || MAC: the shim draws a
 * fresh random nonce and PREPENDS it, so the caller never handles a nonce
 * (CLAUDE.md rule 3, the misuse-resistant shape). Output length is
 * noncebytes + msglen + macbytes. key must be exactly keybytes.
 */
SXT_API int SXT_CALL sxt_secretbox(unsigned char *out, int cap,
                                   const unsigned char *msg, int msglen,
                                   const unsigned char *key, int keylen);
/*
 * Open a box produced by sxt_secretbox. Plaintext length is
 * boxlen - noncebytes - macbytes. Returns SXT_ERR_AUTH (not garbage) on a wrong
 * key or any tampering: the Poly1305 tag is verified before a byte is trusted.
 */
SXT_API int SXT_CALL sxt_secretbox_open(unsigned char *out, int cap,
                                        const unsigned char *box, int boxlen,
                                        const unsigned char *key, int keylen);

/* AEAD (XChaCha20-Poly1305 IETF) length constants. */
SXT_API int SXT_CALL sxt_aead_keybytes(void);
SXT_API int SXT_CALL sxt_aead_noncebytes(void);
SXT_API int SXT_CALL sxt_aead_abytes(void);

/*
 * Like secretbox, but additionally authenticates associated data (ad) without
 * encrypting it (e.g. a header bound to the ciphertext). Same prepend-random-
 * nonce discipline. ad may be NULL with adlen 0. Decrypt returns SXT_ERR_AUTH if
 * the ciphertext OR the supplied ad does not match what was sealed.
 */
SXT_API int SXT_CALL sxt_aead_encrypt(unsigned char *out, int cap,
                                      const unsigned char *msg, int msglen,
                                      const unsigned char *ad, int adlen,
                                      const unsigned char *key, int keylen);
SXT_API int SXT_CALL sxt_aead_decrypt(unsigned char *out, int cap,
                                      const unsigned char *box, int boxlen,
                                      const unsigned char *ad, int adlen,
                                      const unsigned char *key, int keylen);

/*
 * Argon2id (crypto_pwhash) constants and presets. opslimit/memlimit cross into
 * sxt_pwhash / sxt_pwhash_str as DECIMAL STRINGS, because a memlimit can exceed
 * 2^31 and there is no 64-bit foreign int. The opslimit presets fit in an int;
 * the memlimit presets are returned as decimal strings to match how they go in.
 */
SXT_API int SXT_CALL sxt_pwhash_saltbytes(void);
SXT_API int SXT_CALL sxt_pwhash_bytes_min(void);
SXT_API int SXT_CALL sxt_pwhash_strbytes(void);
SXT_API int SXT_CALL sxt_pwhash_opslimit_interactive(void);
SXT_API int SXT_CALL sxt_pwhash_opslimit_moderate(void);
SXT_API int SXT_CALL sxt_pwhash_opslimit_sensitive(void);
/* memlimit presets as decimal strings, filled into a caller buffer (see the
 * string-return rule above): each returns the string length, or -needed. */
SXT_API int SXT_CALL sxt_pwhash_memlimit_interactive(char *out, int cap);
SXT_API int SXT_CALL sxt_pwhash_memlimit_moderate(char *out, int cap);
SXT_API int SXT_CALL sxt_pwhash_memlimit_sensitive(char *out, int cap);

/*
 * Derive an outlen-byte key from a passphrase and salt (salt must be saltbytes;
 * generate it with sxt_randombytes and store it alongside the ciphertext).
 * opslimit/memlimit are decimal strings, parsed and range-checked in the shim.
 * Argon2id, the only sanctioned password KDF. Returns outlen / -needed / error.
 */
SXT_API int SXT_CALL sxt_pwhash(unsigned char *out, int cap, int outlen,
                                const unsigned char *pass, int passlen,
                                const unsigned char *salt, int saltlen,
                                const char *opslimit, const char *memlimit);

/*
 * Hash a passphrase into a self-describing string (crypto_pwhash_str, which
 * packs the salt and the opslimit/memlimit into its output) for storage.
 * Returns the string length excluding the NUL, -needed, or an error.
 */
SXT_API int SXT_CALL sxt_pwhash_str(char *out, int cap,
                                    const unsigned char *pass, int passlen,
                                    const char *opslimit, const char *memlimit);
/*
 * Verify a passphrase against a stored sxt_pwhash_str string (constant time
 * within libsodium). Returns 1 (match), 0 (no match or malformed string). A
 * non-match is a legitimate answer, not an error, so this never enters the
 * error band; compare it with `is`, never the secret itself.
 */
SXT_API int SXT_CALL sxt_pwhash_str_verify(const char *hashstr,
                                           const unsigned char *pass, int passlen);

/* --- Phase 3: streaming AEAD (secretstream) + file helpers ---------------- */

/* secretstream (XChaCha20-Poly1305) length constants and chunk tags. */
SXT_API int SXT_CALL sxt_secretstream_keybytes(void);
SXT_API int SXT_CALL sxt_secretstream_headerbytes(void);
SXT_API int SXT_CALL sxt_secretstream_abytes(void);
SXT_API int SXT_CALL sxt_secretstream_tag_message(void);
SXT_API int SXT_CALL sxt_secretstream_tag_final(void);

/*
 * Streaming AEAD. The state lives C-side in a generation-tagged handle table;
 * script holds only the int handle, and a stale or recycled handle is a clean
 * error, never a crash. The app must free what it opens (there is no
 * deterministic LCB unload hook); sxt_free_stream is idempotent.
 *
 * init_push writes the HEADERBYTES header into header_out and returns a positive
 * handle (or -needed / error). push encrypts one chunk: pass
 * sxt_secretstream_tag_final() on the LAST chunk; that FINAL tag is what makes a
 * truncated stream detectable on pull. init_pull opens a decrypt stream from the
 * header; pull decrypts one chunk and records its tag (read it with
 * sxt_secretstream_last_tag), returning SXT_ERR_AUTH on a wrong key or tampering.
 */
SXT_API int SXT_CALL sxt_secretstream_init_push(unsigned char *header_out, int header_cap,
                                                const unsigned char *key, int keylen);
SXT_API int SXT_CALL sxt_secretstream_push(int handle, unsigned char *out, int cap,
                                           const unsigned char *chunk, int chunklen,
                                           const unsigned char *ad, int adlen, int tag);
SXT_API int SXT_CALL sxt_secretstream_init_pull(const unsigned char *header, int headerlen,
                                                const unsigned char *key, int keylen);
SXT_API int SXT_CALL sxt_secretstream_pull(int handle, unsigned char *out, int cap,
                                           const unsigned char *in, int inlen,
                                           const unsigned char *ad, int adlen);
SXT_API int SXT_CALL sxt_secretstream_last_tag(int handle);
/*
 * Force an explicit rekey of an open stream (crypto_secretstream_..._rekey): both
 * the push and the pull side must call this at the same point in the stream to
 * stay in sync (a one-sided rekey makes the next chunk fail to verify). Gives
 * forward secrecy within a long-lived session without a new handshake. Returns
 * SXT_OK, or SXT_ERR_BADHANDLE for a stale/unknown handle.
 */
SXT_API int SXT_CALL sxt_secretstream_rekey(int handle);
SXT_API void SXT_CALL sxt_free_stream(int handle);

/*
 * C-side file encryption built on secretstream: libsodium reads src in chunks,
 * encrypts, and writes dst, so a multi-gigabyte file never enters a LiveCode
 * Data (the proper replacement for hand-rolled chunk framing). Paths are UTF-8.
 * Returns SXT_OK, SXT_ERR_IO (open/read/write), SXT_ERR_AUTH (a corrupt or
 * TRUNCATED input on decrypt: the missing FINAL tag is detected), or BADARG.
 */
SXT_API int SXT_CALL sxt_encrypt_file(const char *src_path, const char *dst_path,
                                      const unsigned char *key, int keylen);
SXT_API int SXT_CALL sxt_decrypt_file(const char *src_path, const char *dst_path,
                                      const unsigned char *key, int keylen);

/* --- Phase 4: public-key boxes (X25519) + signatures (ed25519) ----------- */

/* box (X25519 + XSalsa20-Poly1305) length constants. */
SXT_API int SXT_CALL sxt_box_publickeybytes(void);
SXT_API int SXT_CALL sxt_box_secretkeybytes(void);
SXT_API int SXT_CALL sxt_box_noncebytes(void);
SXT_API int SXT_CALL sxt_box_macbytes(void);
SXT_API int SXT_CALL sxt_box_sealbytes(void);
SXT_API int SXT_CALL sxt_box_seedbytes(void);   /* seed size for the seeded keypair (32) */

/*
 * Generate an X25519 keypair: writes publickeybytes into pk_out and
 * secretkeybytes into sk_out. Two fixed-size outputs, so this returns SXT_OK or
 * an error (a buffer too small is SXT_ERR_BADARG, since two outputs cannot share
 * one -needed; the LCB always allocates from the length exposers).
 */
SXT_API int SXT_CALL sxt_box_keypair(unsigned char *pk_out, int pk_cap,
                                     unsigned char *sk_out, int sk_cap);
/*
 * Deterministic X25519 keypair from a seedbytes seed (crypto_box_seed_keypair):
 * the same seed always yields the same keypair. This is what lets a single master
 * seed derive an encryption keypair (a subkey from the KDF), so one backup blob
 * reconstructs the whole identity. seed must be exactly seedbytes.
 */
SXT_API int SXT_CALL sxt_box_keypair_from_seed(unsigned char *pk_out, int pk_cap,
                                               unsigned char *sk_out, int sk_cap,
                                               const unsigned char *seed, int seedlen);
/*
 * Authenticated public-key encryption from sender_sk to recipient_pk, with a
 * fresh random nonce prepended (output is noncebytes + msglen + macbytes). Open
 * returns SXT_ERR_AUTH on a wrong key or tampering.
 */
SXT_API int SXT_CALL sxt_box(unsigned char *out, int cap,
                             const unsigned char *msg, int msglen,
                             const unsigned char *recipient_pk, int pklen,
                             const unsigned char *sender_sk, int sklen);
SXT_API int SXT_CALL sxt_box_open(unsigned char *out, int cap,
                                  const unsigned char *box, int boxlen,
                                  const unsigned char *sender_pk, int pklen,
                                  const unsigned char *recipient_sk, int sklen);
/*
 * Anonymous-sender sealed box (crypto_box_seal): the sender needs only the
 * recipient's public key, and the recipient opens with their full keypair.
 * Output is msglen + sealbytes. seal_open returns SXT_ERR_AUTH on failure.
 */
SXT_API int SXT_CALL sxt_box_seal(unsigned char *out, int cap,
                                  const unsigned char *msg, int msglen,
                                  const unsigned char *recipient_pk, int pklen);
SXT_API int SXT_CALL sxt_box_seal_open(unsigned char *out, int cap,
                                       const unsigned char *sealed, int sealedlen,
                                       const unsigned char *recipient_pk, int pklen,
                                       const unsigned char *recipient_sk, int sklen);

/* sign (ed25519) length constants. */
SXT_API int SXT_CALL sxt_sign_publickeybytes(void);
SXT_API int SXT_CALL sxt_sign_secretkeybytes(void);
SXT_API int SXT_CALL sxt_sign_bytes(void);
SXT_API int SXT_CALL sxt_sign_seedbytes(void);

/*
 * ed25519 keypair, random or deterministically from a seedbytes seed. The
 * seeded form is the BEP44-compatible primitive, so a SodiumXT key and a
 * TorrentXT channel key can be one and the same (watch the seed-vs-expanded
 * representation: libsodium's "secret key" is the 64-byte expanded form).
 */
SXT_API int SXT_CALL sxt_sign_keypair(unsigned char *pk_out, int pk_cap,
                                      unsigned char *sk_out, int sk_cap);
SXT_API int SXT_CALL sxt_sign_keypair_from_seed(unsigned char *pk_out, int pk_cap,
                                                unsigned char *sk_out, int sk_cap,
                                                const unsigned char *seed, int seedlen);

/* Detached signature (bytes() long). verify returns 1 (valid) / 0 (invalid or
 * malformed input); like sxt_memequal it never enters the error band. */
SXT_API int SXT_CALL sxt_sign_detached(unsigned char *sig_out, int sig_cap,
                                       const unsigned char *msg, int msglen,
                                       const unsigned char *sk, int sklen);
SXT_API int SXT_CALL sxt_sign_verify_detached(const unsigned char *sig, int siglen,
                                              const unsigned char *msg, int msglen,
                                              const unsigned char *pk, int pklen);

/* Attached signature (signature || message, length bytes() + msglen). sign_open
 * recovers the message or returns SXT_ERR_AUTH if the signature does not verify. */
SXT_API int SXT_CALL sxt_sign(unsigned char *out, int cap,
                              const unsigned char *msg, int msglen,
                              const unsigned char *sk, int sklen);
SXT_API int SXT_CALL sxt_sign_open(unsigned char *out, int cap,
                                   const unsigned char *signed_msg, int signedlen,
                                   const unsigned char *pk, int pklen);

/* --- Phase 5: key derivation, key exchange, padding ----------------------- */

/* kdf (crypto_kdf, BLAKE2b) length constants. */
SXT_API int SXT_CALL sxt_kdf_keybytes(void);
SXT_API int SXT_CALL sxt_kdf_contextbytes(void);
SXT_API int SXT_CALL sxt_kdf_bytes_min(void);
SXT_API int SXT_CALL sxt_kdf_bytes_max(void);

/*
 * Derive subkey number subkey_id (a decimal string: the id is a uint64 and
 * there is no 64-bit foreign int) from a master key, namespaced by an
 * 8-byte context. Different (id, context) give independent subkeys from one
 * master key. subkeylen is in [bytes_min, bytes_max]; master key is keybytes;
 * context is contextbytes. Returns subkeylen, -needed, or an error.
 */
SXT_API int SXT_CALL sxt_kdf_derive(unsigned char *out, int cap, int subkeylen,
                                    const char *subkey_id,
                                    const unsigned char *context, int contextlen,
                                    const unsigned char *masterkey, int masterkeylen);

/* kx (crypto_kx) length constants. */
SXT_API int SXT_CALL sxt_kx_publickeybytes(void);
SXT_API int SXT_CALL sxt_kx_secretkeybytes(void);
SXT_API int SXT_CALL sxt_kx_sessionkeybytes(void);
SXT_API int SXT_CALL sxt_kx_seedbytes(void);   /* seed size for the seeded keypair (32) */

/*
 * Key exchange. kx_keypair makes an X25519 keypair. Each side then derives the
 * SAME pair of session keys: the client's rx equals the server's tx and vice
 * versa, so rx is for receiving and tx for sending. Two fixed-size outputs, so
 * these return SXT_OK / SXT_ERR_AUTH (peer public key rejected) / BADARG.
 */
SXT_API int SXT_CALL sxt_kx_keypair(unsigned char *pk_out, int pk_cap,
                                    unsigned char *sk_out, int sk_cap);
/*
 * Deterministic kx keypair from a seedbytes seed (crypto_kx_seed_keypair): the
 * companion to sxt_box_keypair_from_seed, so a master seed can also derive a
 * key-exchange keypair. seed must be exactly seedbytes.
 */
SXT_API int SXT_CALL sxt_kx_keypair_from_seed(unsigned char *pk_out, int pk_cap,
                                              unsigned char *sk_out, int sk_cap,
                                              const unsigned char *seed, int seedlen);
SXT_API int SXT_CALL sxt_kx_client_session_keys(unsigned char *rx_out, int rx_cap,
                                                unsigned char *tx_out, int tx_cap,
                                                const unsigned char *client_pk, int client_pklen,
                                                const unsigned char *client_sk, int client_sklen,
                                                const unsigned char *server_pk, int server_pklen);
SXT_API int SXT_CALL sxt_kx_server_session_keys(unsigned char *rx_out, int rx_cap,
                                                unsigned char *tx_out, int tx_cap,
                                                const unsigned char *server_pk, int server_pklen,
                                                const unsigned char *server_sk, int server_sklen,
                                                const unsigned char *client_pk, int client_pklen);

/*
 * Length hiding (sodium_pad / sodium_unpad). pad copies in and appends 1..
 * blocksize padding bytes so the result is a multiple of blocksize (this hides
 * the exact message length before encryption); it returns the padded length,
 * -needed, or an error. unpad returns the original unpadded length of a padded
 * buffer (the caller keeps that many leading bytes), or SXT_ERR_ENCODING if the
 * padding is malformed. blocksize must be positive.
 */
SXT_API int SXT_CALL sxt_pad(unsigned char *out, int cap,
                             const unsigned char *in, int inlen, int blocksize);
SXT_API int SXT_CALL sxt_unpad(const unsigned char *in, int inlen, int blocksize);

/* --- Phase 6: streaming / whole-file hashing + unbiased random ------------ */

/*
 * Uniform random integer in [0, upper_bound). Unbiased (rejection sampling),
 * unlike `random() mod n`. upper_bound must be in [1, SXT_MAX_BUFFER]; the
 * result is a non-negative int below the error band. The CSPRNG, so it is safe
 * for shuffles, tokens, and nonces-as-indices (never use the engine random()).
 */
SXT_API int SXT_CALL sxt_randombytes_uniform(int upper_bound);

/*
 * BLAKE2b of a whole file, read chunk by chunk C-side: the bytes never enter a
 * LiveCode Data (the hashing complement to sxt_encrypt_file). key is optional
 * (keylen 0 = unkeyed); outlen is the digest length in [BYTES_MIN, BYTES_MAX].
 * Returns outlen, -needed, SXT_ERR_IO (open/read), or BADARG. Path is UTF-8.
 */
SXT_API int SXT_CALL sxt_hash_file(const char *path, unsigned char *out, int cap, int outlen,
                                   const unsigned char *key, int keylen);

/*
 * Multipart BLAKE2b for data the caller assembles incrementally. The state
 * lives C-side in a generation-tagged handle table (separate from the
 * secretstream table); script holds only the int handle, and a stale handle is
 * a clean error, never a crash. init returns a positive handle (key optional,
 * keylen 0 = unkeyed; outlen captured here is what final produces); update folds
 * in more bytes; final writes the digest and RELEASES the handle (so the common
 * init then update then final path self-cleans). Call sxt_hash_free to abort a
 * state you will not finalize; free is idempotent. final reports -needed (state
 * intact) if the buffer is smaller than the init-time outlen, so a retry is safe.
 */
SXT_API int SXT_CALL sxt_hash_init(const unsigned char *key, int keylen, int outlen);
SXT_API int SXT_CALL sxt_hash_update(int handle, const unsigned char *in, int inlen);
SXT_API int SXT_CALL sxt_hash_final(int handle, unsigned char *out, int cap);
SXT_API void SXT_CALL sxt_hash_free(int handle);

#ifdef __cplusplus
}
#endif
#endif /* SODIUMXT_SODIUM_SHIM_H */
