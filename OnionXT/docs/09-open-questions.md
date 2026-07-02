# 09 - Open Questions

The honest to-do list: design decisions not yet settled, and limits not yet closed. Ship each labeled
for what it is; do not present any of these as solved (CLAUDE.md honesty rule). Resolve them in the
docs and code in the same change that closes them.

## Anonymity limits (inherited from Tor; likely permanent)

1. **Traffic correlation / global passive adversary.** OnionXT does not defend against an adversary
   who watches both ends of Tor and correlates timing/volume. Padding and cover traffic (`sxPad`,
   fixed-cadence heartbeats) raise the cost but do not close it. Document as out of scope.
2. **Local daemon trust.** The tor daemon on loopback is in the trusted base: it sees SOCKS targets and,
   if it generates them, onion keys. Deriving onion keys from a SodiumXT seed (doc 04) keeps the
   identity key from originating in the daemon, but the daemon still routes your traffic. How much to
   invest in detecting a subverted local Tor (binary verification in Mode B, control-protocol sanity
   checks) is open.
3. **Descriptor and activity timing.** Publishing and fetching onion descriptors, and connection
   timing, leak "when is this identity online" to the hash-ring directories and observers. Epoch-scoped
   rotating addresses help unlinkability but add republish cost. The right cadence is unsettled.

## Design decisions to settle

4. **Epoch-scoped rotating onions: worth the cost?** Rotating the onion address per Riptide epoch gives
   unlinkability but forces a descriptor republish (seconds of unreachability) each rotation. Quantify
   the latency and decide default cadence, or make it a per-channel policy.
5. **Client authorization by default?** v3 client auth (doc 04) makes an onion unreachable to anyone
   without the x25519 key, closing address-phishing, at the cost of distributing that key. Should
   Riptide channels use it by default, or only for high-sensitivity contacts?
6. **Reads: chunk delivery vs app framing.** OnionXT delivers raw inbound chunks to a stream callback
   and lets the app frame. Should OnionXT offer an optional length-prefixed framing helper (still no
   crypto), or stay strictly byte-transparent? Leaning transparent, but confirm against Riptide's
   envelope needs.
7. **How much lifecycle to own (Mode B).** Launching/supervising a bundled tor is convenient but adds a
   trusted binary and distribution weight (doc 07). Decide whether the reference product bundles tor or
   documents installing it; the default is documented-install.
8. **Multiplexing many streams over few circuits.** Many concurrent `oxDial`s to different onions is
   fine, but a chatty app may want to reuse a single onion connection for multiple logical streams.
   Whether OnionXT multiplexes (its own stream ids over one socket) or opens one socket per stream is
   open; one-per-stream is simplest and the v1 default.

## Upstream dependencies (tracked in doc 08)

9. **SodiumXT ed25519 seed-to-expanded-key** for deterministic onions: **SHIPPED** (ABI 6,
   `sxSignSeedToExpandedKey`). `oxCreateServiceFromSeed` can compose it directly; no longer a blocker.
10. **SodiumXT HMAC-SHA256** for SAFECOOKIE auth: **SHIPPED** (ABI 6, `sxHmacSha256`). **SodiumXT
    SHA3-256** for the offline address checksum remains **DEFERRED** (the only open upstream item;
    libsodium has no SHA-3, so it would mean bundling non-libsodium crypto). Add it only when offline
    `.onion` emit/validate is genuinely needed.

## Testing and conformance

11. **What is the conformance vector here?** SodiumXT and Riptide have crypto/wire KATs. OnionXT's
    determinism claim (seed -> `.onion`) has a known answer worth pinning as a vector once the
    expansion helper exists; the SOCKS/control wire behaviour can only be integration-tested against a
    real daemon. Decide the split between a pinned derivation vector and an on-engine interop harness.
12. **Negative-path coverage.** Bad address, stalled daemon, wrong cookie, double close, peer vanishing
    mid-handshake, descriptor never publishing. These are the security-relevant tests; enumerate and
    script them (Phase 6) before declaring robustness.
