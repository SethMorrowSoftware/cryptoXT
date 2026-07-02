# 08 - Capabilities Required (Upstream Gaps)

OnionXT composes SodiumXT for all cryptography (CLAUDE.md rule 1) and the OXT engine for all socket
I/O. A few narrow capabilities it wants are not yet available in those. This is the honest list, each
with the OnionXT feature it blocks, options, and a recommendation. The family rule holds: a needed
crypto primitive is an **upstream SodiumXT feature request landed first**, never a hand-rolled hash in
OnionXT.

**Status:** gaps #1 (ed25519 seed to expanded key) and #3 (HMAC-SHA256) are now **shipped in SodiumXT
ABI 6** as `sxSignSeedToExpandedKey` and `sxHmacSha256`. Only gap #2 (SHA3-256) remains open, and it is
deferrable (see its entry).

## SodiumXT gaps

### 1. ed25519 seed -> expanded key (for deterministic onion services)

- **Needed by:** `oxCreateServiceFromSeed` and any reproducible-address flow (doc 04). `ADD_ONION
  ED25519-V3:<key>` wants the 64-byte expanded ed25519 secret key (`SHA-512(seed)`, clamped, split into
  scalar `a` and prefix `RH`), not libsodium's `seed || pubkey` secret key.
- **Options:**
  a. Add a dedicated SodiumXT helper, for example `sxSignSeedToExpandedKey(pSeed) returns Data` (65 or
     64 bytes), which does the SHA-512 + clamp internally with `crypto_hash_sha512` and libsodium's
     scalar clamping. Cleanest and least error-prone.
  b. Expose `crypto_hash_sha512` as `sxSha512` and do the clamp in OnionXT script. Smaller SodiumXT
     change, but puts a fiddly clamp in script.
  c. Defer: only support Tor-generated keys (`NEW:ED25519-V3`) and persist the returned `PrivateKey`.
     No reproducible-from-seed address, but no upstream dependency.
- **Recommendation:** land (a) upstream in SodiumXT (small, well-scoped, testable with a known-answer
  vector), then compose it. Until then, ship deferral (c) so the rest of OnionXT is unblocked.
- **STATUS: SHIPPED (SodiumXT ABI 6).** Landed as `sxSignSeedToExpandedKey(pSeed) returns Data` (the
  64-byte expanded key = `SHA-512(seed)` with the ed25519 scalar clamp), verified against an
  independent known-answer vector. `oxCreateServiceFromSeed` composes it; no deferral needed.

### 2. SHA3-256 (for the v3 onion address checksum)

- **Needed by:** `oxAddressFromPublicKey` (to emit a correct 2-byte checksum) and `oxIsValidAddress`
  (to validate a pasted address offline). The checksum is `SHA3-256(".onion checksum" || PUBKEY ||
  VERSION)[:2]`.
- **Options:**
  a. Add `sxSha3_256` to SodiumXT. Note libsodium's stable API does not include SHA-3/Keccak; it would
     come from libsodium's optional/experimental surface or a tiny vetted Keccak added to the shim.
     This is a larger ask than the SHA-512 helper.
  b. Defer: get your own address from `ADD_ONION`'s `ServiceID` (Tor computes the checksum), and rely
     on Tor's connect-time descriptor-signature check to authenticate a peer's address rather than a
     local checksum verify. base32 decode still recovers the peer's public key without SHA3.
- **Recommendation:** defer (b) for v1; the checksum is a nicety, not a security dependency (the
  descriptor signature is the real authentication). Add (a) only if offline address emission/validation
  becomes a real need.
- **STATUS: DEFERRED (the only remaining gap).** libsodium has no SHA-3, so this is the one primitive
  that would mean bundling non-libsodium crypto into SodiumXT; it stays deferred until offline `.onion`
  emit/validate is genuinely needed. Address recovery (base32 decode -> ed25519 public key) and
  connect-time authentication both work without it.

### 3. HMAC-SHA256 (for SAFECOOKIE control auth)

- **Needed by:** the preferred SAFECOOKIE control-auth method (doc 03), which verifies a server hash
  and computes a client hash, both HMAC-SHA256 over the cookie and nonces.
- **Options:**
  a. Add `sxHmacSha256(pKey, pMsg)` to SodiumXT (libsodium has `crypto_auth_hmacsha256`, so this is a
     small, natural addition).
  b. Defer: use COOKIE auth (send the cookie hex) or HASHEDPASSWORD or NULL, none of which need HMAC.
     Over a loopback control port this is acceptable.
- **Recommendation:** defer (b) for v1 (COOKIE over loopback is fine), and add (a) upstream when
  hardening, since SAFECOOKIE avoids sending the cookie in the clear even on loopback.
- **STATUS: SHIPPED (SodiumXT ABI 6).** Landed as `sxHmacSha256(pKey, pMessage) returns Data`
  (crypto_auth_hmacsha256, multipart form so the key may be any length), verified against RFC 4231
  Test Case 2. SAFECOOKIE control auth can now be implemented directly; COOKIE auth remains a fine
  fallback.

## Engine capabilities to confirm (not gaps, but Phase 0 unknowns)

These are assumed to exist in OXT (they exist in LiveCode); confirm and record the exact behaviour in
Phase 0, because the whole core rests on them:

- Asynchronous sockets: `open socket ... with message`, `read from socket ... for N with message`,
  `write to socket`, `accept connections on <port> with message`, `close socket`, `socketError` /
  `socketTimeout` messages, and `the socketTimeoutInterval`.
- Binary discipline: byte-exact `read`/`write`, `byte x to y of`, `numToByte`, `byteToNum`,
  `binaryEncode`, `binaryDecode`, with no Unicode reinterpretation on the socket path.
- Reading a file's raw bytes (the control cookie): `open file ... for binary read` / `url
  ("binfile:...")`.
- For Mode B lifecycle (doc 07): `open process` / shelling out to launch and signal a child tor.

## Not needed from anyone

- No new BitTorrent capability (that is TorrentXT's domain, tracked in Riptide's own
  capabilities-required doc).
- No Tor-side change: OnionXT uses stock SOCKS5 and the stock control protocol against an unmodified
  tor daemon.
