# OnionXT Implementation Plan

The phased build order. Each phase has a goal, concrete deliverables, a "done when" bar, and the
risks that phase exists to retire. The guiding principle is the family's: **do the smallest thing
that a real tor daemon can prove, then build on proven ground.** Nothing is "done" on a claim; it is
done when it has shaken hands with an actual daemon on an OXT engine.

Read [CLAUDE.md](CLAUDE.md) and the `docs/` spine first. House style and the static gate
(`tools/check-livecodescript.py`) apply to every phase that touches script.

## Phase 0 - Ground truth and decisions (no code that ships)

**Goal:** remove the unknowns before writing protocol code.

- Confirm on an OXT engine that the socket commands OnionXT depends on exist and behave:
  `open socket ... with message`, `read from socket ... for N with message`, `write to socket`,
  `accept connections on <port> with message`, `close socket`, `the socketTimeoutInterval`, and
  binary-safe `byte` indexing / `numToByte` / `byteToNum` / `binaryEncode` / `binaryDecode`. Record
  the exact behaviours (does a callback read deliver exactly N bytes, or up to N?) in CLAUDE.md.
- Stand up a reference tor daemon and pin the `torrc` used for bring-up (doc 03 and doc 07 have the
  lines: `ControlPort 9051`, an auth method, and `SocksPort 9050`). Note the Tor Browser variant
  (`9150`/`9151`).
- Enumerate the SodiumXT capability gaps (doc 08): the ed25519 seed-to-expanded-key step for
  deterministic onions (needs SHA-512), and the optional v3-address checksum (needs SHA3-256). Decide
  per gap: land it upstream in SodiumXT first, compute it in script, or defer by letting Tor generate
  and return the key.

**Done when:** the socket behaviours are recorded as fact (not assumption), a daemon is reachable on
loopback, and each capability gap has an owner and a decision.

**Risk retired:** building a protocol on a socket API that turns out to behave differently than the
docs assume.

## Phase 1 - SOCKS5 dial (outbound), the thinnest slice

**Goal:** dial a known-good onion address through Tor and exchange bytes.

- Implement the SOCKS5 client as a callback-driven state machine (doc 02): greet `05 01 00`, expect
  `05 00`, send a CONNECT with ATYP=3 to `<host>:<port>`, parse the reply, expose the tunneled socket.
- Public surface (doc 05): `oxDial pHost, pPort` reporting a stream handle through `the result`, with
  `oxWrite`, `oxRead` (callback), and `oxCloseStream`. Map every non-zero SOCKS REP, including Tor's
  0xF0..0xF6, to a clear error string.
- Test target: any stable v3 onion that serves bytes (a known service, or the Phase 3 listener once it
  exists; for Phase 1 use an external known-good address).

**Done when:** on the engine, `oxDial` to a real onion returns a usable stream and a round-trip of a
few bytes succeeds, and a bad address returns a clean mapped error, not a hang.

**Risk retired:** binary socket framing in livecodescript, and the async read state machine.

## Phase 2 - Control-port connect and authenticate

**Goal:** hold an authenticated control connection.

- `PROTOCOLINFO 1` to discover offered auth methods and the cookie path; then NULL, SAFECOOKIE/COOKIE,
  or HashedControlPassword auth in that priority (doc 03). CRLF line framing with the `250-` vs `250 `
  distinction.
- Public surface: `oxConnectControl pPort` and `oxDisconnectControl`, plus an internal
  send-command / await-reply state machine that other phases reuse.

**Done when:** on the engine, OnionXT authenticates to the control port with at least the cookie
method, `GETINFO version` returns, and a wrong cookie fails closed with a clear error.

**Risk retired:** the control auth dance and CRLF reply reassembly.

## Phase 3 - Publish an onion service and accept inbound

**Goal:** be reachable at your own `.onion`.

- `ADD_ONION NEW:ED25519-V3 Port=<virt>,127.0.0.1:<local>` (doc 03); capture `ServiceID` and (unless
  discarded) `PrivateKey`. Start `accept connections on <local> with message onPeer` first, so
  forwarded connections are answered (doc, socket gotcha 5).
- Public surface: `oxCreateService pVirtualPort, pLocalPort` returning the `.onion` address and a
  service handle; `oxRemoveService`; an app-settable callback for inbound peers.
- Wire `HS_DESC` events (Phase 6 formalizes events) enough to know when the descriptor is published and
  the service is actually reachable.

**Done when:** on the engine, OnionXT publishes a service, and a second process (curl through Tor, or a
second engine instance) connects to the `.onion` and reaches the local accept handler.

**Risk retired:** inbound path, the local-listener-before-publish ordering, descriptor timing.

## Phase 4 - The two-instance round trip (the headline milestone)

**Goal:** two OXT instances talk over Tor with no server and no clearnet.

- Instance A: Phase 3 publishes a service and accepts. Instance B: Phase 1 dials A's `.onion`. A sealed
  payload (SodiumXT `sxSeal` / `sxSecretBox`, chosen by the app) travels B->A and A->B.
- Build the `examples/onion-roundtrip` harness that scripts both roles with on-screen status.

**Done when:** on two engines (or two processes), a SodiumXT-sealed message makes the full trip and
back, authenticated, with both IPs hidden behind Tor.

**Risk retired:** end-to-end integration; this is the proof OnionXT is real.

## Phase 5 - Deterministic onions from a seed (compose SodiumXT)

**Goal:** an app's `.onion` address is reproducible from its master seed, so identity survives a
reinstall and doubles as a published public key.

- Derive the ed25519 identity from the seed with SodiumXT (`sxSignKeypairFromSeed`), expand it to Tor's
  64-byte ED25519-V3 form (SHA-512 of the seed, clamped; doc 04, doc 08), base64 it, and pass it to
  `ADD_ONION ED25519-V3:<key> ...` for a fixed address.
- Add `oxAddressFromPublicKey` / `oxPublicKeyFromAddress` (base32 encode/decode of the 32-byte pubkey
  plus version; checksum verification is optional and needs SHA3-256, doc 08).

**Done when:** the same seed yields the same `.onion` on every run, verified against a known-answer
vector, and the address round-trips to the ed25519 public key.

**Risk retired:** the expanded-key gotcha (the single most likely place to get subtly wrong), and the
address<->key mapping.

## Phase 6 - Events, bootstrap UX, and the negative paths

**Goal:** production-grade robustness.

- `SETEVENTS` for `STATUS_CLIENT` (bootstrap %), `CIRC`, `STREAM`, `HS_DESC`; route `650` lines to an
  event state machine and surface bootstrap progress at <= ~4 Hz.
- Timeouts on every handshake, idempotent teardown for every stream/service/connection, and explicit
  handling of `socketError`, mid-handshake peer loss, and duplicate close.
- Write the negative tests first (bad address, stalled daemon, wrong cookie, double close).

**Done when:** a cold-start bootstrap shows progress and never freezes the UI, and every negative path
returns a clean error instead of hanging or crashing.

**Risk retired:** the "works in the demo, hangs in the field" failure mode.

## Phase 7 - Riptide transport integration

**Goal:** OnionXT becomes Riptide's `ox` transport (doc 06).

- Implement the transport interface Riptide expects (dial by rendezvous address, listen, send/recv an
  envelope), mapping Riptide's rendezvous to an onion address derived from the shared/identity key.
- Advertise `ox` transport support in the Riptide prekey bundle; let a channel negotiate `ox` vs `bt`.
- Feed the self-authenticating onion address into Riptide's first-contact verification (doc 06).

**Done when:** a Riptide channel completes a message exchange entirely over OnionXT, and the threat
model doc can move "no IP anonymity" from "unsolved" to "available via the ox transport."

**Risk retired:** the integration that motivates the whole project.

## Phase 8 - Optional: tor lifecycle and native helpers

**Goal:** convenience and performance, only where measured need justifies it.

- Optionally launch and supervise a bundled tor binary via `open process` (doc 07): write a temp
  `torrc`, start tor, wait for bootstrap, and shut it down on exit. This is a convenience layer; the
  assume-running path stays the default and the tested one.
- Optionally move hot or awkward pure-compute pieces (binary framing, base32, the ed25519 expansion)
  into a thin LCB or C helper, under the FFI rules in CLAUDE.md, only if an on-engine pass shows script
  is too slow or too fragile.

**Done when:** the optional pieces exist behind clean flags, the default path is unchanged, and any
shim passes ASan/UBSan and carries an ABI guard.

**Risk retired:** scope creep; this phase is explicitly last and explicitly optional.

## Cross-cutting: what "done" always means

- The static gate passes, the code is ASCII with no em-dashes, and behaviour is confirmed on a real
  tor daemon on an OXT engine (or clearly flagged as awaiting that pass).
- Crypto is SodiumXT, never hand-rolled. Network targets resolve in Tor, never locally. Every opened
  resource has an idempotent close. Every wire error fails closed.
- The honesty rules hold: no open item (traffic correlation, local-daemon trust, descriptor metadata)
  is presented as solved.
