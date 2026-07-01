# 02 - The SOCKS5 Dial Path

This is the byte-level spec for OnionXT's outbound path: connecting to Tor's SOCKS5 proxy and asking
it to open a stream to a `.onion` (or clearnet) target. It is RFC 1928 plus Tor's SOCKS extensions.
Build and parse against this field by field, in binary (`byte`, `numToByte`, `byteToNum`,
`binaryEncode`, `binaryDecode`), never with `char` / `line` / `word`.

## Endpoints

- System tor: SOCKS on `127.0.0.1:9050`.
- Tor Browser: SOCKS on `127.0.0.1:9150`.

Make the port configurable but default to 9050 and lock the host to loopback.

## Step 1: the method-negotiation greeting

Client sends 3 bytes:

```
+------+----------+----------+
| 0x05 |   0x01   |   0x00   |
+------+----------+----------+
  VER   NMETHODS   METHOD(0) = NO AUTHENTICATION REQUIRED
```

Server replies with 2 bytes:

```
+------+--------+
| 0x05 | METHOD |
+------+--------+
```

- `METHOD == 0x00` (no auth): proceed. Tor's loopback SOCKS needs no authentication.
- `METHOD == 0xFF`: no acceptable method. Fail closed.
- Any other method: OnionXT does not offer it; fail closed. (Do not silently attempt username/password
  auth; on loopback it is unnecessary and its absence is a misconfiguration to surface, not paper over.)

## Step 2: the CONNECT request

Client sends:

```
+------+------+------+------+----------+----------+----------+
| 0x05 | 0x01 | 0x00 | ATYP | DST.ADDR | PORT_HI  | PORT_LO  |
+------+------+------+------+----------+----------+----------+
  VER   CMD    RSV    ATYP   (variable)  big-endian 16-bit port
         CONNECT      =0x03
```

- `CMD = 0x01` (CONNECT). OnionXT only needs CONNECT (BIND and UDP ASSOCIATE are not used).
- `RSV = 0x00`.
- **`ATYP = 0x03` (DOMAINNAME) for every target.** This is the anonymity-critical choice: with ATYP=3,
  Tor resolves the name itself. For a `.onion` that is the only thing that works; for a clearnet host
  it prevents a deanonymizing local DNS lookup. Never use ATYP=1 (IPv4) or ATYP=4 (IPv6) from a name
  you resolved yourself.
- `DST.ADDR` for ATYP=3 is a length-prefixed string: one length byte `N`, then `N` bytes of the host.
  For a v3 onion, `N = 62` (`56` base32 chars + `.onion`). Example host bytes: the ASCII of
  `abcdefghijklmnopqrstuvwxyz234567...onion`.
- `PORT` is the 2-byte big-endian virtual port of the service (for example 80 -> `0x00 0x50`).

`binaryEncode` sketch (verify on-engine): build the fixed head, append `numToByte(length of tHost)`,
append the host bytes, append the two port bytes with `binaryEncode("S", tPort)` (network-order
short) or `numToByte(tPort div 256)` and `numToByte(tPort mod 256)`.

## Step 3: the reply

Server replies:

```
+------+------+------+------+----------+----------+----------+
| 0x05 | REP  | 0x00 | ATYP | BND.ADDR | PORT_HI  | PORT_LO  |
+------+------+------+------+----------+----------+----------+
  VER    REP    RSV    ATYP   (variable)  bound port
```

- Read the first 4 bytes, then read the variable `BND.ADDR` whose length depends on `ATYP`
  (`0x01`: 4 bytes, `0x04`: 16 bytes, `0x03`: one length byte then that many), then read the 2 port
  bytes. Frame it exactly; a callback read may return short (CLAUDE.md socket gotcha 3).
- `REP == 0x00`: success. The socket is now a transparent tunnel to the target. Everything you write is
  delivered to the target; everything the target sends arrives to read. OnionXT hands this stream to
  the caller and does no further SOCKS processing.
- `REP != 0x00`: failure. Close the socket and return a mapped error.

## REP code mapping

Standard RFC 1928 codes plus Tor's onion-specific extensions (the ones a user actually hits):

| REP  | Meaning (map to a clear message)                                    |
|------|---------------------------------------------------------------------|
| 0x00 | success                                                             |
| 0x01 | general SOCKS server failure                                         |
| 0x02 | connection not allowed by ruleset                                   |
| 0x03 | network unreachable                                                 |
| 0x04 | host unreachable                                                    |
| 0x05 | connection refused                                                  |
| 0x06 | TTL expired                                                         |
| 0x07 | command not supported                                              |
| 0x08 | address type not supported                                         |
| 0xF0 | onion service descriptor cannot be found (wrong or offline address) |
| 0xF1 | onion service descriptor is invalid                                 |
| 0xF2 | onion service introduction failed                                   |
| 0xF3 | onion service rendezvous failed                                     |
| 0xF4 | onion service missing client authorization                          |
| 0xF5 | onion service wrong client authorization                            |
| 0xF6 | onion service invalid address                                       |

The `0xF*` band is where "you dialed a dead or wrong onion" shows up; give those human messages, not a
raw code.

## State machine (callback-driven)

Do not block. Model the dial as states advanced by socket callbacks:

```
IDLE
  -> open socket to proxy (with message socketReady / socketError)
GREETING_SENT      (wrote 05 01 00; read 2 bytes with message)
METHOD_OK          (got 05 00; wrote CONNECT; read 4 bytes with message)
REPLY_HEAD         (parsed VER REP RSV ATYP; read BND.ADDR length; read the rest with message)
REPLY_DONE         (REP==0 -> CONNECTED and hand up the stream; else close + error)
CONNECTED          (caller now owns read/write on the socket)
FAILED / CLOSED
```

Set `the socketTimeoutInterval` (or an explicit timer) around the handshake: a bootstrapping daemon
will accept the TCP connection and then stall, and a silent stall is the worst failure. On timeout,
`close socket` and surface a clean error.

## What OnionXT does and does not do here

- It **does** open the tunnel and hand back a raw byte stream.
- It **does not** encrypt, frame, or interpret the bytes on that stream. If the app wants
  confidentiality and integrity (it should), it seals with SodiumXT before `oxWrite` and opens with
  SodiumXT after `oxRead`. Tor protects the path; SodiumXT protects the payload.
