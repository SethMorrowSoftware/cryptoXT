# 03 - The Tor Control Protocol Path

This is the command-level spec for OnionXT's inbound and management path: authenticating to Tor's
control port and using it to publish onion services and read events. The control protocol is
line-based text (CRLF-delimited), so it is friendlier than SOCKS, but the framing and auth rules are
exact. Full reference: the Tor control-spec (`control-spec.txt`); this doc captures the subset OnionXT
needs.

## Endpoint and torrc

- System tor: control on `127.0.0.1:9051`. Tor Browser: `127.0.0.1:9151`.
- The daemon must be configured to expose the control port and an auth method. The reference `torrc`
  for bring-up:

```
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
# OR, instead of cookie auth, a hashed password (generate with: tor --hash-password "secret"):
# HashedControlPassword 16:....
```

Document these exact lines in the example so a tester reproduces the environment.

## Line framing

- Send each command as one line terminated by CRLF (`\r\n`). Set `the lineDelimiter to crlf` right
  where you parse replies, and restore it after (it is global mutable state; CLAUDE.md gotcha 7).
- Replies are one or more lines, each `<3-digit-status><sep><text>`:
  - `<sep> = "-"` (`250-...`): a mid-reply line, more follow.
  - `<sep> = "+"` (`250+...`): begins a multi-line data block, ended by a line containing only `.`.
  - `<sep> = " "` (`250 ...`): the final line of the reply.
- Read until you see a line whose separator is a space; that terminates the reply. Route unsolicited
  `650` lines (events) to the event state machine, not to the pending-command continuation.

Status codes: `2xx` success (`250 OK`), `4xx`/`5xx` errors (`515` bad auth, `514` auth required,
`512`/`513` syntax, `551` internal). Fail closed on any non-`2xx`.

## Step 1: discover the auth method (PROTOCOLINFO)

Before authenticating (this command is allowed pre-auth), send:

```
PROTOCOLINFO 1
```

The reply reports the offered methods and, for cookie auth, the cookie file path:

```
250-PROTOCOLINFO 1
250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/var/lib/tor/control_auth_cookie"
250-VERSION Tor="0.4.x.x"
250 OK
```

Parse `METHODS=` and `COOKIEFILE=`. Prefer methods in this order: `SAFECOOKIE` > `COOKIE` > `NULL` >
`HASHEDPASSWORD`. Treat the `COOKIEFILE` path as authoritative; do not guess it.

## Step 2: authenticate

Send exactly one of these, matching the chosen method:

- **NULL** (no auth configured): `AUTHENTICATE`
- **COOKIE**: read the 32 raw bytes of the cookie file, hex-encode them, send `AUTHENTICATE <hex>`.
- **SAFECOOKIE** (preferred; avoids sending the cookie in the clear): a challenge-response:
  1. `AUTHCHALLENGE SAFECOOKIE <ClientNonce-hex>` where ClientNonce is 32 random bytes (SodiumXT
     `sxRandomBytes(32)`).
  2. Reply gives `SERVERHASH=<hex>` and `SERVERNONCE=<hex>`.
  3. Verify `SERVERHASH == HMAC-SHA256(key = "Tor safe cookie authentication server-to-controller
     hash", msg = CookieBytes || ClientNonce || ServerNonce)` in constant time (SodiumXT
     `sxMemEqual`). If it fails, the control port is not the real Tor; abort.
  4. Send `AUTHENTICATE <ClientHash-hex>` where `ClientHash = HMAC-SHA256(key = "Tor safe cookie
     authentication controller-to-server hash", msg = CookieBytes || ClientNonce || ServerNonce)`.
- **HASHEDPASSWORD**: `AUTHENTICATE "<password>"` (the password quoted; the daemon stores only its
  hash).

Expect `250 OK`. `515` means the credential was wrong; `514` means you skipped auth. Note: SAFECOOKIE
needs HMAC-SHA256, which is a SodiumXT capability gap today (doc 08); until it lands, COOKIE auth
(plain hex over loopback) is the pragmatic path, and NULL/HASHEDPASSWORD need no HMAC.

## Step 3: publish an onion service (ADD_ONION)

Ephemeral service, Tor generates the key:

```
ADD_ONION NEW:ED25519-V3 Port=80,127.0.0.1:8080
```

Reply:

```
250-ServiceID=<56-char-base32>
250-PrivateKey=ED25519-V3:<base64 of the 64-byte expanded secret key>
250 OK
```

- `ServiceID` is your address minus `.onion`. The full address is `ServiceID & ".onion"`.
- `PrivateKey` is returned once; persist it if the address must survive a restart, or pass
  `Flags=DiscardPK` if you never need to recreate it.
- `Port=VIRT,127.0.0.1:LOCAL` maps the onion's virtual port `VIRT` to your loopback listener `LOCAL`.
  Repeat `Port=` for multiple mappings.

Bring-your-own-key (deterministic, reproducible address; see doc 04):

```
ADD_ONION ED25519-V3:<base64 expanded key> Port=80,127.0.0.1:8080
```

Useful flags: `Flags=Detach` (service outlives the control connection), `Flags=DiscardPK` (do not
return the key). Without `Detach`, the service dies when the control connection closes, which is often
the right default for a session-scoped service.

Remove a service: `DEL_ONION <ServiceID>` -> `250 OK`.

## Step 4: listen locally FIRST

Before or immediately after `ADD_ONION`, the app must be accepting on the loopback `LOCAL` port so Tor
can forward inbound onion connections:

```
accept connections on 8080 with message onPeer   -- bind loopback only
```

Ordering matters: if the descriptor publishes and a peer connects before the listener exists, the
connection is refused. Start the listener first (CLAUDE.md socket gotcha 5).

## Step 5: events and bootstrap (SETEVENTS)

Subscribe to async events:

```
SETEVENTS STATUS_CLIENT CIRC STREAM HS_DESC
```

- `STATUS_CLIENT` carries `BOOTSTRAP PROGRESS=NN` lines: drive a bootstrap progress bar from these
  (coalesce to <= ~4 Hz). Or poll `GETINFO status/bootstrap-phase`.
- `HS_DESC` reports when your onion descriptor is uploaded and the service is reachable, and when a
  descriptor fetch for a target you are dialing succeeds or fails.
- Events arrive as `650` lines interleaved with command replies; the reader must demultiplex `650`
  (event) from `2xx`/`4xx`/`5xx` (command reply) and route accordingly.

## State machine

```
DISCONNECTED
  -> open socket to control port
CONNECTED         (send PROTOCOLINFO 1; read reply)
AUTH_METHOD_KNOWN (send AUTHENTICATE / AUTHCHALLENGE; read reply)
AUTHENTICATED     (ready for ADD_ONION, GETINFO, SETEVENTS, ...)
SERVICE_PUBLISHED (got ServiceID; local listener running; awaiting HS_DESC upload)
READY             (descriptor uploaded; reachable)
  (650 event lines route to the event handler throughout AUTHENTICATED..READY)
```

Every command is send-line-then-await-reply; keep a single in-flight command queue so replies match
commands, and never block the interpreter thread waiting for one.
