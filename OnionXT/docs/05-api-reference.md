# 05 - Public API Reference (`ox*`)

The public surface OnionXT exposes to an app or to Riptide. Shapes follow the family convention:
**commands report status through `the result`** (and yield handles through out-style conventions),
**functions return a value**. All are livecodescript handlers in the v1 core. This is the target
surface for the plan; it is not implemented yet.

Naming: public `oxPascalCase`. Handles are small integers or the engine's socket ids; a stale handle
is a clean error, never a crash. Every open has a matching idempotent close.

## Configuration

| Handler | Kind | Purpose |
|---|---|---|
| `oxSetSocksPort pPort` | command | Set the loopback SOCKS port (default 9050; Tor Browser 9150). |
| `oxSetControlPort pPort` | command | Set the loopback control port (default 9051; Tor Browser 9151). |
| `oxVersion()` | function | OnionXT version string, and (once connected) the tor version from `GETINFO version`. |

Host is always `127.0.0.1`; it is not configurable (loopback-locked, CLAUDE.md socket gotcha 6).

## Control connection and bootstrap

| Handler | Kind | Purpose |
|---|---|---|
| `oxConnectControl` | command | Open + authenticate the control connection (PROTOCOLINFO, then the best auth method). Reports success/failure in `the result`. |
| `oxDisconnectControl` | command | Close the control connection. Idempotent. |
| `oxBootstrapProgress()` | function | 0..100 from `STATUS_CLIENT` / `GETINFO status/bootstrap-phase`. |
| `oxIsReady()` | function | True once bootstrapped to 100 and (if a service is published) its descriptor is uploaded. |

The app sets a callback (for example `oxSetStatusCallback pHandlerName`) to receive coalesced
bootstrap / event updates at <= ~4 Hz.

## Outbound: dialing

| Handler | Kind | Purpose |
|---|---|---|
| `oxDial pHost, pPort` | command | SOCKS5 CONNECT (ATYP=3) to `pHost:pPort` through Tor. Reports a stream handle in `the result`, or a mapped SOCKS error. `pHost` is a `.onion` or clearnet name; it is resolved in Tor, never locally. |
| `oxWrite pStream, pData` | command | Write `Data` (already sealed by the app) to the stream. |
| `oxSetStreamCallback pStream, pHandlerName` | command | Register the handler the engine-side read loop calls with inbound `Data` on this stream. |
| `oxCloseStream pStream` | command | Close and forget the stream. Idempotent. |

Reads are asynchronous: OnionXT reads the tunneled socket `with message` and hands each chunk of
`Data` to the registered stream callback. The app reassembles application-level frames (OnionXT does
not know the app's framing).

## Inbound: onion services

| Handler | Kind | Purpose |
|---|---|---|
| `oxCreateService pVirtualPort, pLocalPort` | command | `ADD_ONION NEW:ED25519-V3` mapping `pVirtualPort` -> `127.0.0.1:pLocalPort`, after ensuring a loopback listener is accepting on `pLocalPort`. Reports the full `<56>.onion` address and a service handle. |
| `oxCreateServiceFromSeed pSeed, pVirtualPort, pLocalPort` | command | As above, but deterministic: derive the ed25519 key from `pSeed` via SodiumXT and pass the expanded key (needs the doc 08 helper), so the address is reproducible. |
| `oxRemoveService pService` | command | `DEL_ONION` and stop the listener. Idempotent. |
| `oxServiceAddress pService` | function | The `.onion` address of a published service. |
| `oxSetPeerCallback pHandlerName` | command | Register the handler called when a peer connects to a published service (delivers a new inbound stream handle). |

## Address helpers (pure, no network)

| Handler | Kind | Purpose |
|---|---|---|
| `oxAddressFromPublicKey pEd25519Pub` | function | Encode a 32-byte ed25519 public key as a `<56>.onion` address (checksum needs SHA3-256, doc 08). |
| `oxPublicKeyFromAddress pOnionAddress` | function | Decode a `.onion` back to its 32-byte ed25519 public key. base32-decode + strip checksum/version. |
| `oxIsValidAddress pOnionAddress` | function | Structural + (when SHA3-256 is available) checksum validation of a pasted address. |

## Callbacks the app implements

| Callback | Delivered when |
|---|---|
| status callback | bootstrap progress, circuit/descriptor events (coalesced). |
| stream callback (per dialed stream) | inbound `Data` arrives on that stream. |
| peer callback (per service) | a remote peer connects to a published service; yields a new inbound stream handle to register a stream callback on. |

## Error model

- Commands set `the result` to empty on success, or to a clear, human-readable error string on
  failure (mapped SOCKS REP codes, control `4xx`/`5xx`, timeouts, closed sockets). Never a raw numeric
  code with no explanation.
- Every wire error fails closed and tears the resource down; there is no silent fallback to an
  unproxied or unauthenticated path (CLAUDE.md rule 4).

## What is deliberately NOT here

- No encryption, framing, or session logic: OnionXT moves bytes; the app / Riptide seals them with
  SodiumXT and owns their framing.
- No blocking read/connect variants: the whole surface is callback-driven so the one interpreter
  thread never blocks on the network (CLAUDE.md async model).
