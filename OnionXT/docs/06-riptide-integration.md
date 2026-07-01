# 06 - OnionXT as a Riptide Transport

OnionXT is useful standalone, but its reason to exist in the family is to be Riptide's metadata-privacy
transport. This document sketches how OnionXT plugs in as the `ox` transport alongside Riptide's
default `bt` (BitTorrent) transport, and how it upgrades Riptide's threat model.

## The transport seam

Riptide's design is transport-agnostic: it seals a message with SodiumXT, then hands the ciphertext to
a transport that provides rendezvous, dial, listen, and send/recv. Today that transport is `bt` (DHT
rendezvous + swarm/peer-wire). OnionXT provides a second implementation of the same seam:

| Riptide needs | `bt` transport (TorrentXT) | `ox` transport (OnionXT) |
|---|---|---|
| rendezvous point | DHT key from shared secret + epoch | onion address from the identity ed25519 key (doc 04) |
| listen / be reachable | swarm membership, BEP10 peer wire | published v3 onion service + loopback accept |
| dial a peer | connect to swarm peers | `oxDial <peer>.onion` through SOCKS5 |
| send / recv bytes | peer-wire messages | `oxWrite` / stream callback |
| identity <-> address | separate key distribution | the onion address IS the ed25519 key |

Riptide should define this as an explicit transport interface (its implementation plan already treats
transports as pluggable), and OnionXT implements it. The envelope layer, KDF label registry, epoch
clock, and associated-data binding do not change: only where the sealed bytes travel changes.

## Rendezvous mapping

- A contact's Riptide identity already includes an ed25519 signing key. Map that key (or a per-contact
  subkey derived through Riptide's KDF registry) to an onion address with `oxAddressFromPublicKey`. The
  contact publishes a service at the matching address with `oxCreateServiceFromSeed`.
- Because the address authenticates the key, Riptide's **first-contact verification gets stronger**:
  dialing the address and completing the onion rendezvous proves the far end holds the key, closing the
  rung-3 MITM that a DHT-controlling attacker could otherwise attempt. Riptide should still pin the
  address and bind it into the contact record, so a later address swap is detected.
- For unlinkable, rotating rendezvous, derive an **epoch-scoped** onion key from the shared secret and
  the epoch (Riptide's clock), so the address rotates and a passive observer cannot link epochs. This
  costs an onion-service republish per epoch; treat cadence as a tuning knob (descriptor publication is
  not free).

## What Riptide gains

- Moves "no IP anonymity by default" and "rendezvous metadata leak" from **unsolved** to **available on
  the `ox` transport** in Riptide's threat model. Peers no longer exchange IPs; DHT lookups and direct
  peer links stop leaking the fact and endpoints of contact.
- Keeps working through NAT and hostile networks: onion services need no port forwarding and connect
  outbound only, and MQTT-over-WebSocket-style reach concerns do not apply.

## What Riptide must still do (honesty)

- **Seal everything with SodiumXT.** OnionXT does not encrypt. Tor protects the path; the message-level
  "right recipient, intact content, no replay" guarantees are Riptide's `sx*`-based envelopes, exactly
  as on the `bt` transport.
- **Not claim more than Tor gives.** Traffic correlation, local-daemon trust, and descriptor timing
  remain (doc 01, doc 09). The `ox` transport is a strong IP-metadata improvement, not anonymity
  against a global passive adversary.
- **Negotiate, not assume.** A channel advertises which transports each side speaks (in the prekey
  bundle) and negotiates `ox` vs `bt`, possibly using `ox` for the interactive path and `bt` for bulk
  file torrents, mirroring the hybrid-transport idea. Fall back cleanly when Tor is unavailable, and
  make the fallback visible (do not silently downgrade anonymity).

## Hybrid picture

```
Riptide channel
   control / live / interactive  ->  ox transport (OnionXT)  ->  anonymous, self-authenticating
   bulk file torrents            ->  bt transport (TorrentXT) ->  swarm throughput
   (payload sealed by SodiumXT either way; transport is negotiated, never assumed)
```

This is the same composition principle the family runs on: OnionXT adds a transport and a naming
property, invents no crypto, and lets Riptide decide when to use it.
