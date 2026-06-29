# Plan: replace TorrentXT's crypto with SodiumXT

Status: **proposal**. This lives in the SodiumXT repo because that is the repo in
scope here; the actual edits land in the TorrentXT repo. Items marked
**[confirm]** are assumptions about TorrentXT's current code that must be checked
against its source before implementing.

## Why

TorrentXT's optional encryption uses OXT's stock
`encrypt ... using "aes-256-cbc" with password ...`. Two problems:

1. **Weak key derivation.** That path runs OpenSSL's legacy `EVP_BytesToKey`
   (a few rounds of MD5), not a memory-hard KDF. A passphrase is brute-forceable
   far faster than it should be.
2. **No cipher-level authentication.** AES-CBC alone is malleable and unauthenticated:
   a flipped ciphertext bit silently corrupts plaintext rather than being rejected.
   TorrentXT's hand-rolled chunked-file framing **[confirm]** does not add a MAC,
   so tampering and truncation go undetected.

SodiumXT fixes both: Argon2id for the KDF, and authenticated ciphers (secretbox /
AEAD / secretstream) that fail closed. It is also a reusable building block, so
TorrentXT drops hand-rolled crypto and calls `sx*`.

## The two crypto sites in TorrentXT [confirm]

1. **Small in-memory blobs** (e.g. an encrypted settings/metadata value):
   `encrypt <data> using "aes-256-cbc" with password <pass>` and the matching
   `decrypt`.
2. **Whole-file encryption** done in script with hand-rolled ~4 MiB chunks and
   AES-CBC framing (the lesson that motivated SodiumXT's C-side file helpers).

Find both with a grep for `encrypt`, `decrypt`, and the chunk loop in TorrentXT,
and confirm there are no other call sites.

## Mapping

| TorrentXT today | SodiumXT replacement |
|---|---|
| `encrypt X using "aes-256-cbc" with password P` | `sxSecretBox(X, key)` where `key = sxPwHash(textEncode(P,"utf-8"), salt, 32, "2", sxPwMemInteractive())` |
| `decrypt ...` | re-derive `key` from the stored salt + ops/mem, then `sxSecretBoxOpen(box, key)` (throws on wrong pass / tamper) |
| weak `EVP_BytesToKey` KDF | Argon2id via `sxPwHash`; store the random salt and the ops/mem with the data |
| hand-rolled chunked AES-CBC file framing | `sxEncryptFile` / `sxDecryptFile` (secretstream: per-chunk auth, ordering, truncation detection, all C-side) |
| no integrity check | every form carries a Poly1305 tag; open/decrypt throw on tamper |

If the data being encrypted is large but already in memory, `sxAeadEncrypt` (with
a small associated-data header) is the authenticated equivalent; for anything that
should not be resident twice, prefer the file helpers.

## On-disk format and migration

SodiumXT output is **not** wire-compatible with the old aes-256-cbc data, so plan
for coexistence:

- **Version the container.** Prefix new blobs with a 1-byte version (or a short
  magic), e.g. `0x01` = "SodiumXT secretbox". Lay it out as
  `version || salt(16) || opslimit || memlimit || nonce+ciphertext+mac`, where
  `sxSecretBox` already prepends the nonce, so in practice: `version || salt ||
  ops || mem || sxSecretBox(...)`. (Or use `sxPwHashStr`-style packing if you
  prefer to keep ops/mem with the hash.)
- **Read both on open.** If the version byte / magic is present, use SodiumXT;
  otherwise fall back to the old `decrypt ... using "aes-256-cbc"` path so
  existing data still opens.
- **Re-encrypt on write.** When the user next saves, write the new format. Old
  data thus migrates lazily; no bulk conversion step needed.
- **[confirm]** whether any TorrentXT data is shared across peers/versions on the
  wire (if so, the format change needs a protocol-version bump, not just a local
  container version).

## Wiring the dependency

- Bundle the `sodiumxt` native library inside TorrentXT the same way SodiumXT
  ships it: `src/code/<arch>-<platform>/sodiumxt.{so,dll,dylib}` (the committed
  binaries from this repo's CI, all five platforms).
- Add `src/sodium.lcb` to TorrentXT's extension (or depend on the installed
  SodiumXT extension so `org.openxtalk.library.sodium` resolves).
- TorrentXT's helpers then `textEncode` the passphrase and call `sx*`. Compare any
  secrets with `sxMemEqual`, never `is`.

## Phased plan

1. **Inventory [confirm].** Grep TorrentXT for every `encrypt`/`decrypt`/chunk-loop
   site; list them and the exact data shapes.
2. **Container + helpers.** Add `txCryptoSeal` / `txCryptoOpen` wrappers in
   TorrentXT that implement the versioned container over `sxPwHash` + `sxSecretBox`,
   with the old-format fallback on open.
3. **Swap the in-memory site** to the wrappers; keep the old decrypt path for reads.
4. **Swap the file site** to `sxEncryptFile` / `sxDecryptFile`.
5. **Tests:** round-trip new format; open a stored old-format blob (fallback);
   wrong passphrase and a flipped byte both throw; a truncated file fails to
   decrypt. Mirror SodiumXT's tamper/wrong-key style.
6. **Docs:** note the format version and the lazy migration in TorrentXT's README.

## Open questions to resolve against TorrentXT's source [confirm]

- Exact call sites and data shapes for the two crypto uses.
- Whether encrypted data crosses the wire between peers (protocol-version impact).
- Where TorrentXT wants the cost knob (interactive vs sensitive) surfaced to users.
- Whether TorrentXT already vendors any native libs under `src/code/`, to match
  its packaging convention.

## Effort

Small-to-moderate and low-risk once the inventory is confirmed: the heavy lifting
(the KDF, the authenticated ciphers, the C-side file loop, the cross-platform
binaries) is already done and on-engine-verified in SodiumXT. The new code in
TorrentXT is the versioned container, the read-both-formats fallback, and the call
swaps.
