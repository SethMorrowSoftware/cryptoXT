# 00 - Overview and Architecture

## The one-sentence version

OnionXT lets an xTalk app dial anonymously and be reachable serverlessly by speaking two simple wire
protocols (SOCKS5 and the Tor control protocol) to a locally-running tor daemon, and it gets
self-authenticating rendezvous for free because a v3 onion address is an ed25519 public key.

## The three capabilities

1. **Anonymous outbound (SOCKS5).** Any TCP connection an app would make (to a peer, a tracker, an
   MQTT broker, an HTTP API) can instead be dialed through Tor's SOCKS5 proxy on `127.0.0.1:9050`.
   The far end sees a Tor exit or, for a `.onion`, nothing but an onion circuit; it never sees the
   app's IP. See [02-socks5-client.md](02-socks5-client.md).
2. **Serverless inbound (onion services via the control port).** Through the control port on
   `127.0.0.1:9051`, an app asks Tor to publish a **v3 onion service**. Tor advertises the service in
   the distributed hash ring, and forwards any inbound onion connection to a loopback port the app
   listens on. The app is now reachable at a global, stable `.onion` address with no public IP, no
   port forwarding, and no server. See [03-control-port.md](03-control-port.md).
3. **Self-authenticating rendezvous (the onion address is a public key).** A v3 `.onion` address is
   `base32(ed25519_pubkey || checksum || version)`. Reaching that address is a cryptographic proof you
   are talking to the holder of that ed25519 key. So the address doubles as a published identity key
   and a rendezvous point at once, with no CA, no DNS, and no MITM-able key exchange. See
   [04-onion-rendezvous.md](04-onion-rendezvous.md).

## Where OnionXT sits in the family

```
SodiumXT (sx*)   crypto: ed25519 identity, key derivation, AEAD, secretstream, sealing
TorrentXT (bt*)  the BitTorrent DHT / swarm transport (Riptide's default transport)
OnionXT  (ox*)   the Tor transport + onion rendezvous (this repo)
      |
Riptide (rt*)    composes the above into secure channels; picks a transport per channel
```

OnionXT is a **transport and naming layer**. It adds no cryptography (SodiumXT does that) and no
BitTorrent (TorrentXT does that). It is to Tor what TorrentXT is to libtorrent, except that it wraps
two text/binary wire protocols over ordinary engine sockets instead of a C++ engine, so in its v1
form it ships **no native code at all**.

## The runtime picture

```
   +-------------------- one OXT app instance --------------------+
   |                                                              |
   |  app / Riptide            OnionXT (ox*)                      |
   |     |  oxDial ----------->  SOCKS5 state machine  --------------> 127.0.0.1:9050 (tor SOCKS)
   |     |  oxCreateService -->  control state machine  -------------> 127.0.0.1:9051 (tor control)
   |     |  onPeer  <---------   accept loop           <-------------- 127.0.0.1:<local> (tor forwards
   |     |                                                              inbound onion traffic here)
   |     |  payload sealing via SodiumXT (sx*)                         |
   +--------------------------------------------------------------+    |
                                                                       v
                                                            the Tor network (onion circuits)
```

The tor daemon is a separate process. OnionXT never routes, never crypto-processes onion layers, and
never touches the network except through the daemon's loopback ports.

## Why script, not a native binding

The engine already has everything the core needs: `open socket`, `read from socket ... with message`,
`write to socket`, `accept connections on port`. SOCKS5 is a handful of fixed byte sequences and the
control protocol is line-based text. Wrapping a C Tor-control library would add a native build matrix,
an ABI surface, and a bundling problem for zero capability gain. So OnionXT is livecodescript first,
with a thin LCB/C helper reserved for the two narrow pure-compute jobs script does badly (fast binary
framing and the ed25519 key expansion), and only if an on-engine pass shows script cannot carry them.
See [08-capabilities-required.md](08-capabilities-required.md).

## Reading order

1. This overview.
2. [01-threat-model.md](01-threat-model.md) - what Tor buys and what it does not; the honesty rules.
3. [02-socks5-client.md](02-socks5-client.md) and [03-control-port.md](03-control-port.md) - the wire
   protocols, byte and line exact.
4. [04-onion-rendezvous.md](04-onion-rendezvous.md) - the onion-address-is-a-public-key idea and
   deterministic onions.
5. [05-api-reference.md](05-api-reference.md) - the public `ox*` surface.
6. [06-riptide-integration.md](06-riptide-integration.md) - OnionXT as a Riptide transport.
7. [07-tor-lifecycle.md](07-tor-lifecycle.md), [08-capabilities-required.md](08-capabilities-required.md),
   [09-open-questions.md](09-open-questions.md) - the edges.
