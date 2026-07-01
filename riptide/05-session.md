# 05. Pairwise session

This document defines Riptide's live one-to-one channel: how two peers turn a first contact into a
keyed, forward-secret conversation over the peer wire, and how that same conversation can be hidden
inside a real, lawful BitTorrent transfer. It realizes channels C2 (phantom swarm) and C3
(cover-seed) from [../brainstorm.md](../brainstorm.md).

Everything here obeys the constitution in [03-conventions.md](03-conventions.md): canonical bencode
(3.2), the primitive table and nonce discipline (3.3), the KDF label registry (3.4), the envelope
and associated-data rules (3.5), the message-type registry (3.6), the BEP10 `rp1` carrier (3.8), the
epoch clock (3.9), and the error model (3.10). Notation is from 3.11 (`x || y`, `be64(n)`,
`bencode(...)`, `DHT.*`, and the `sx*` calls). Identity keys, the prekey bundle, and first-contact
verification are defined in [02-identity.md](02-identity.md) and are used, not redefined, here. This
document does not restate any derivation or format already pinned in the foundation; it composes
them.

## Registry additions

This document introduces **no new message types and no new salts**. It uses only entries already
reserved in [03-conventions.md](03-conventions.md):

- KDF contexts `rp-sess0` (session root key) and `rp-txrx0` (directional keys), both from the 3.4
  registry.
- Message types `0x20` handshake-init, `0x21` handshake-resp, `0x22` data, `0x23` rekey, all from the
  session range `0x20-0x2F` in 3.6, carried as the 1-byte `rp1` subtype (3.8).

It introduces **one domain-separation tag** and, for one optional mode, **one candidate KDF label**:

- `rp-cvrsd` (11 ASCII bytes) is a literal domain-separation tag passed to `sxHash`, not a KDF
  context. Per the 3.4 note, derivations from a public key or shared secret via `sxHash` (rather than
  `sxKdfDerive`) carry an explicit tag defined at their point of use; `rp-cvrsd` is that tag for the
  cover-seed recognition token (5.7.2). It does not go in the 8-byte KDF context registry.
- **Open registry item:** the optional recognition-key mode of cover-seed (5.7.3) wants a per-epoch
  ed25519 signing seed derived with `sxKdfDerive` from the shared recognition secret. That needs a
  new **8-byte** KDF context (proposed `rp-cvsig`) added to the 3.4 registry when this mode is
  implemented. It is listed here as an open item, not yet claimed, because the default identity-key
  mode does not need it and this document should not amend the constitution unilaterally.

Two peer-wire operations that this document assumes TorrentXT exposes, and that
[11-capabilities-required.md](11-capabilities-required.md) formalizes, are written here in the same
style as the `DHT.*` operations of 3.11:

- `PW.connect(ip, port) -> conn` : open a BitTorrent peer connection and complete the BEP10 extended
  handshake, advertising the `rp1` extension (3.8).
- `PW.handshakeDict(conn) -> dict` : the remote peer's BEP10 extended-handshake dictionary (the
  `m` map plus any extra top-level keys), needed for cover-seed recognition (section 5).
- `PW.send(conn, "rp1", payload)` / `PW.recv(conn, "rp1") -> payload` : send or receive one `rp1`
  extension message. The payload is the `[subtype : 1 byte][body : bytes]` frame of 3.8.
- `PW.onConnect(id, handler)` : in cover-seed mode, a callback invoked for each new peer that joins
  the swarm for infohash `id`, giving access to that peer's extended-handshake dictionary.

If any of these names change when doc 11 is written, change them there and here in one pass; nothing
else in this document depends on their spelling.

## 5.1 What a session is

A **session** is a bidirectional, authenticated, ordered byte channel between two identities `A` and
`B`, carried as `rp1` extension messages (3.8) on a single BitTorrent peer connection. It has three
cryptographic parts:

1. A **handshake** (5.3) that runs an X3DH-style agreement over the prekey bundle of
   [02-identity.md](02-identity.md) plus a fresh ephemeral key, yielding a 32-byte **session root
   key** `RK` and, from it, two **directional keys** `k_tx` and `k_rx`.
2. Two **secretstream streams** (5.4), one per direction, each initialized under one directional key.
   Every application message is one secretstream chunk framed as subtype `0x22`. Ordering,
   per-message authentication, and truncation detection come from secretstream for free (3.3, C2).
3. **Rekey** (5.6): forward secrecy over the life of the session, by advancing the secretstream key
   or by a fresh ephemeral exchange, framed as subtype `0x23`.

A session is **live**: both peers must be online at once (threat-model N7). The asynchronous
counterpart, where the recipient is offline, is the mailbox of [06-mailbox.md](06-mailbox.md), which
reuses the same handshake output as its initial root key.

The connection is driven by the state machine of section 6.

## 5.2 The two rendezvous variants

Two ways to reach the point where both peers share a live `rp1` connection. The handshake (5.3) is
identical in both; only how the peers find each other and who moves first differs.

- **Interactive (C2 phantom swarm).** Both peers are online and share a pairwise secret already (a
  prior session, or a mailbox exchange). They compute a rotating rendezvous DHT id from that secret
  and the current epoch (the `rp-rndzv` derivation of [04-rendezvous.md](04-rendezvous.md)), announce
  and look each other up, and connect. The handshake then runs live, both ephemeral keys fresh. This
  is the realtime core: the swarm membership is the channel, and the "torrent" is a MacGuffin
  (brainstorm C2).

- **Mailbox-bootstrapped.** The peers do not yet share a live connection, or `A` does not yet know
  `B` is online. `A` fetches `B`'s prekey bundle from the DHT (published per 2.4) and sends the
  handshake-init as an asynchronous mailbox message ([06-mailbox.md](06-mailbox.md)); when `B` comes
  online and drains its inbox, it completes the handshake and (if still wanted) opens a live `rp1`
  connection using the rendezvous id the two now share. This variant gives forward secrecy from the
  first message even though the initiator never saw the responder online (2.4).

- **Cover-seed (C3).** A special case of interactive rendezvous where the meeting place is a real,
  popular torrent's swarm rather than a derived phantom id, and recognition happens in the BEP10
  extended handshake rather than at a derived DHT id. Fully specified in section 5.

## 5.3 The handshake (X3DH-style agreement)

The handshake establishes `RK`, `k_tx`, `k_rx` from long-term and ephemeral keys. It follows the
shape of X3DH: the initiator combines the responder's long-term and prekey material with its own
identity and a fresh ephemeral, so the responder can reconstruct the same secret from its stored
secret keys, and neither a stolen long-term key alone nor a captured transcript alone recovers the
session.

### 5.3.1 Inputs

From [02-identity.md](02-identity.md), each party has an identity signing key `IK` (ed25519), an
identity encryption key `IK_x` (X25519, for `sxBox`), and a kx keypair `KX` (crypto_kx). The
responder `B` additionally publishes a prekey bundle (2.4): a signed prekey `SPK_B` and, if
available, a one-time prekey `OPK_B`. The initiator `A` generates a fresh ephemeral X25519 keypair
`EK_A` for this handshake and throws it away after (this is the source of forward secrecy and of the
initiator's contribution).

The identity encryption keys and the kx keys are, per the capability note in 2.2, generated once and
stored beside the seed until the seeded-keypair capability lands; the derivations below treat them as
given inputs and do not depend on how they were produced.

### 5.3.2 The agreement (what secret is computed)

Riptide computes the X3DH master secret as the KDF of a concatenation of Diffie-Hellman results,
using the SodiumXT primitives of 3.3. Because SodiumXT exposes `sxBox` (authenticated X25519 +
XSalsa20-Poly1305) and `sxKeyExchange*` (crypto_kx), not a bare scalar-mult, Riptide realizes each
"DH" as a **crypto_kx agreement between the two relevant keypairs** and concatenates the resulting
32-byte shared keys. crypto_kx over a pair of X25519 keypairs is exactly an X25519 DH followed by a
BLAKE2b of the two public keys and the shared point, so it is a sound, misuse-resistant stand-in for
the raw DH that X3DH specifies, and it keeps Riptide inside the "never touch a bare primitive" rule
(principle 1, 3.3).

The four agreements, following X3DH's DH1..DH4 (omit DH4 when `B` published no one-time prekey):

```
DH1 = kx( IK_x_A , SPK_B )        -- initiator identity  x responder signed prekey
DH2 = kx( EK_A   , IK_x_B )       -- initiator ephemeral x responder identity
DH3 = kx( EK_A   , SPK_B )        -- initiator ephemeral x responder signed prekey
DH4 = kx( EK_A   , OPK_B )        -- initiator ephemeral x responder one-time prekey (if present)
```

Each `kx(myKeypair, theirPub)` is computed with the crypto_kx calls so both sides derive an
identical 32-byte value. The initiator (client role) and responder (server role) call the matching
form so their `rx`/`tx` line up; Riptide takes the agreed **rx** value of each exchange as that DH
output (an arbitrary but fixed convention, pinned by the conformance vectors in
[12-conformance-vectors.md](12-conformance-vectors.md)):

```
-- initiator A, for DH1 (A is client, B is "server" holding SPK_B):
sxKeyExchangeClient IK_x_A_pub, IK_x_A_sec, SPK_B, tRx, tTx
put tRx into DH1
-- responder B reconstructs the same DH1 with the server form:
sxKeyExchangeServer SPK_B_pub, SPK_B_sec, IK_x_A_pub, tRx, tTx
put tRx into DH1
```

DH2, DH3, DH4 are computed the same way with the keypairs named above. The order of the two roles
in each `kx` is fixed by which side holds the ephemeral so that client/server assignment is
unambiguous and both peers agree.

The X3DH secret and the session keys:

```
DHM  = DH1 || DH2 || DH3 || DH4            -- or DH1 || DH2 || DH3 when no OPK
KM   = sxHash(DHM, 32)                     -- compress the concatenation to a 32-byte KDF master key
RK   = sxKdfDerive(KM, "0", "rp-sess0", 32)          -- 3.4: session root key
k_tx = sxKdfDerive(RK, "0", "rp-txrx0", 32)          -- 3.4: id 0 = tx (this peer sends with it)
k_rx = sxKdfDerive(RK, "1", "rp-txrx0", 32)          -- 3.4: id 1 = rx (this peer receives with it)
```

`sxKdfDerive` requires a 32-byte secret master key, so the variable-length `DHM` is first compressed
to `KM` with `sxHash` before it can be a KDF master (3.4 note). `rp-sess0` id `0` derives `RK`;
`rp-txrx0` id `0` derives the sender key and id `1` the receiver key.

**Directional agreement.** Both peers derive the same `RK`, hence the same `(id0, id1)` pair. To make
the two directions consistent, the peers agree on a canonical orientation: the peer with the
**lexicographically smaller `IK` public key** treats id `0` as `k_tx` and id `1` as `k_rx`; the other
peer swaps them (id `0` is its `k_rx`, id `1` its `k_tx`). This is the same "sort the identity keys"
trick that makes safety numbers symmetric (2.5); it gives each side a distinct send key without an
extra round trip and with no reused key across directions.

### 5.3.3 The wire flow (interactive, over rp1)

Preconditions: both peers are connected over `rp1` (5.2 interactive rendezvous; the connection exists
and both advertised `rp1`). `A` is the initiator (it fetched or already holds `B`'s prekey bundle and
verified `spk_sig` and `B`'s identity per 2.4 and 2.5). All control payloads are canonical bencode
dicts (3.2) carried as the body of an `rp1` frame; the subtype byte precedes the bencode.

```
1. A: verify B's prekey bundle.
      sxSignVerifyDetached(spk_sig, SPK_B_pub, IK_B_pub)  MUST be true, else abort (2.4).
2. A: generate ephemeral.
      sxBoxKeypair EK_A_pub, EK_A_sec
3. A: compute DH1..DH4 and RK, k_tx, k_rx as in 5.3.2.
4. A -> B: handshake-init, subtype 0x20, body =
      bencode({
        v:   1,
        t:   0x20,
        ik:  IK_A_pub,           -- A's identity signing key (32), so B can bind the session to A
        ix:  IK_x_A_pub,         -- A's identity X25519 key (32), an input to DH1
        ek:  EK_A_pub,           -- A's ephemeral X25519 public key (32), input to DH2..DH4
        sp:  <SPK_B fingerprint> -- sxHash(SPK_B_pub, 16), tells B which signed prekey A used
        op:  <OPK_B fingerprint OR empty> -- sxHash(OPK_B_pub, 16) if a one-time prekey was used
        ep:  epoch,              -- 3.9 epoch, binds the handshake to a time window (anti-replay)
        g:   sig                 -- ed25519 proof of possession, see below
      })
   where sig = sxSignDetached(bencode(handshake dict without g), IK_A_sec).
   The signature covers every other field, so IK_A, EK_A, the prekey fingerprints, and the
   epoch are all authenticated as coming from A. This is A's explicit authentication (mutual
   auth, 5.3.4).
5. B: on receiving 0x20:
      - reject if v != 1 or t != 0x20 or ep is not in {epoch-1, epoch, epoch+1} (3.9 drift, 3.10).
      - look up its own SPK (and OPK, if op is non-empty) by the fingerprints sp/op; if the OPK
        fingerprint names a prekey B has already consumed, abort (one-time prekeys are single use,
        2.7): this is the replay defense for the async variant.
      - verify g: sxSignVerifyDetached(g, bencode(dict without g), ik) MUST be true. This binds
        the whole init to A's identity key and is what stops an attacker replaying or forging an
        init under someone else's name.
      - reconstruct DH1..DH4 with the server-form kx calls (5.3.2), derive RK, k_tx, k_rx.
      - consume the named OPK (delete its secret so it can never be reused).
6. B: initialize its send stream (5.4) and answer.
      put sxSecretStreamInitPush(k_tx_B, tHeaderB) into hPushB     -- k_tx_B is B's send key
   B -> A: handshake-resp, subtype 0x21, body =
      bencode({
        v:  1,
        t:  0x21,
        hd: tHeaderB,            -- B's secretstream header (24 bytes), for A to init its pull
        ac: sxHashKeyed(bencode({ik:IK_A_pub, ek:EK_A_pub, ep:epoch}), RK, 32),
                                 -- a key confirmation MAC: proves B derived the same RK
        g:  sxSignDetached(bencode(resp dict without g), IK_B_pub_sec)
      })
7. A: on receiving 0x21:
      - verify g against IK_B_pub (B's identity, which A already holds and verified, 2.5). This is
        B's explicit authentication: only the real B can sign with IK_B.
      - verify ac with sxMemEqual against sxHashKeyed(bencode({ik:IK_A_pub, ek:EK_A_pub,
        ep:epoch}), RK, 32). A mismatch means B did not derive the same RK (wrong key, MITM, or
        tamper): abort (3.10, fail closed). Constant-time compare, never `is` (3.3).
      - put sxSecretStreamInitPull(k_rx_A, hd) into hPullA         -- A can now decrypt B's stream
8. A: initialize its own send stream and send its header so B can decrypt A's stream.
      put sxSecretStreamInitPush(k_tx_A, tHeaderA) into hPushA
   A -> B: data-carrying header, subtype 0x21 (a second 0x21, direction A->B), body =
      bencode({ v:1, t:0x21, hd: tHeaderA })
   (This second 0x21 needs no signature: the stream it opens is keyed by k_tx_A, which only the
   real A could have derived, so authenticity is already established. It is a header exchange,
   not a fresh authentication.)
9. B: put sxSecretStreamInitPull(k_rx_B, hd) into hPullB
```

After step 9 both peers hold a push handle and a pull handle and the session is **established**
(section 6). Application data flows as subtype `0x22` (5.4). The ephemeral secret `EK_A_sec` is
zeroed and dropped by `A`; `B` has already deleted the consumed `OPK`.

Note on `sxKeyExchange*` public keys: crypto_kx keypairs and box (`IK_x`) keypairs are both X25519,
so the same public bytes serve as the `theirPub` argument to the kx calls in 5.3.2. Where a bundle
field is documented in 2.4 as an X25519 public key, it is used directly.

### 5.3.4 Mutual authentication

- **A is authenticated to B** by field `g` in the init (step 4): an ed25519 signature over the whole
  init under `IK_A_sec`. Only the holder of A's identity secret can produce it, and it covers `EK_A`
  and the epoch, so it cannot be lifted onto a different ephemeral or replayed into another epoch.
- **B is authenticated to A** two ways that must both hold: the signature `g` in the resp (step 6)
  under `IK_B_sec`, and the key-confirmation MAC `ac`, which proves `B` actually derived the shared
  `RK` (a signature alone would not prove key agreement; the MAC binds identity to the derived key).
- **The identities themselves** are trusted because `A` verified `B`'s `IK` out of band or via the
  key-transparency log before the handshake (2.5), and `B` learns and pins `A`'s `IK` from field `ik`
  in the init. On a first inbound handshake from an unknown `A`, `B` treats `ik` as
  trust-on-first-use and SHOULD prompt for safety-number verification (2.5) before treating the
  contact as verified; the session is still confidential and integrity-protected in the meantime, it
  is only the binding of the key to a human that is pending.

### 5.3.5 Downgrade and replay resistance

- **No cipher or version negotiation exists.** Every party requires `v = 1` and the fixed primitives
  of 3.3; there is no "supported ciphers" list an attacker could strip down. A downgrade attack has
  nothing to bite on (principle 1).
- **Epoch binding.** The init's `ep` is inside the signature and is checked against the current epoch
  window (step 5). A handshake captured in epoch `n` cannot be replayed in epoch `n+2`.
- **One-time-prekey consumption** makes a captured init non-replayable within its epoch as well: `B`
  deletes the named `OPK` on first use, so a replayed init that names an already-consumed `OPK` is
  rejected (step 5). When no `OPK` was available and only `SPK` was used, replay within the epoch
  window is still possible at the handshake layer, but it buys the attacker nothing: it cannot derive
  `RK` (that needs `EK_A_sec`, which it does not have), so it cannot produce a valid `ac` or read any
  data. The consequence is at most a duplicate session offer, which `B` MAY suppress by remembering
  recently seen `(ik, ek, ep)` tuples.
- **The key-confirmation MAC `ac`** ensures that a man-in-the-middle who forwarded a modified init
  (for example swapping `EK_A`) cannot complete: it would not know `RK`, so `A`'s check in step 7
  fails closed.

## 5.4 The live session over rp1

Once established, each direction is a secretstream stream (3.3). One application message is one
`sxSecretStreamPush` chunk, sent as an `rp1` frame with subtype `0x22`.

### 5.4.1 Sending

```
1. sender: cipherChunk = sxSecretStreamPush(hPush, pad(plaintext, 1024), tAd, false)
      - pad to the 1024-byte peer-wire bucket (3.5.2) so length stops leaking.
      - tAd is empty for a normal data message. (The stream already binds order and direction; the
        epoch/seq AD dict of 3.5.1 is for the record channels, not needed inside a secretstream,
        whose internal per-chunk state already authenticates position.)
      - pFinal is false for every message except the last (5.5).
2. sender -> peer: PW.send(conn, "rp1", 0x22 || cipherChunk)
```

### 5.4.2 Receiving

```
1. peer: payload = PW.recv(conn, "rp1"); split subtype (0x22) and cipherChunk.
2. peer: chunk = sxSecretStreamPull(hPull, cipherChunk, tAd, rTag)
      - throws on wrong key or any tamper -> the connection is torn down (3.10, fail closed).
3. peer: if sxIsFinalTag(rTag) is true, the sender has closed this direction cleanly (5.5).
         otherwise: plaintext = sxUnpad(chunk, 1024); deliver plaintext.
```

Ordering and integrity are secretstream's: chunk `n` only decrypts if chunks `0..n-1` were pulled in
order, so an injected, dropped, duplicated, or reordered `0x22` frame fails to authenticate and tears
down the connection. This is the C2 property "ordering + per-chunk auth + truncation detection built
in" (brainstorm C2, 3.3), obtained for free rather than hand-rolled.

### 5.4.3 Keepalive

A live session needs to detect a dead peer and to keep NAT bindings and the BitTorrent connection
open. Riptide does not add a new subtype for this; it sends an **empty data message** as a keepalive:

```
every KEEPALIVE_SECONDS (default 30) of send-idle:
   send a 0x22 frame carrying sxSecretStreamPush(hPush, pad(0-byte plaintext, 1024), "", false)
receiver: sxUnpad yields 0 bytes -> deliver nothing, but the successful pull advances the stream and
   proves liveness.
```

Because the keepalive is a real, authenticated, padded stream chunk, it is indistinguishable on the
wire from a short data message, so it does not add a fingerprint (this matters in cover-seed, section
5). If no frame (data or keepalive) arrives within KEEPALIVE_TIMEOUT (default 90 s), the peer is
presumed gone and the connection moves to `closed` (section 6).

## 5.5 Closing a direction

A clean close of one direction is a final secretstream chunk:

```
closing sender: send a 0x22 frame carrying
      sxSecretStreamPush(hPush, pad(optional-final-plaintext, 1024), "", true)   -- pFinal = true
      then sxFreeStream hPush.
receiver: sxSecretStreamPull returns and sxIsFinalTag(rTag) is true -> this direction is closed and
      truncation-checked (a cut-off stream would have failed to produce a FINAL tag, so a truncation
      attack is detectable, 3.3). sxFreeStream hPull.
```

When both directions have sent their FINAL tag (or the connection drops), the session is `closed` and
both handles are freed. `sxFreeStream` is idempotent (api-reference), so freeing on both a clean close
and a teardown path is safe.

## 5.6 Rekey (forward secrecy over the session lifetime)

Secretstream gives forward secrecy for data already sent (past chunks cannot be recovered from the
current state), but a very long-lived session benefits from periodically refreshing key material so
that a compromise at time `t` cannot decrypt traffic sent well before `t`. Riptide offers two rekey
strengths, both framed as subtype `0x23`.

### 5.6.1 Light rekey (secretstream rekey)

The cheap path advances the secretstream key in place, discarding the old key so earlier chunks are
unrecoverable even from the live state. It costs one control frame per direction and no new DH.

```
1. initiator -> peer: 0x23 body = bencode({ v:1, t:0x23, r: "s" })   -- "s" = secretstream rekey
2. both peers: advance their push and pull streams' internal key via `sxSecretStreamRekey`
   (available in SodiumXT ABI 5; both sides must rekey at the same stream point or the next chunk
   fails to open).
   The rekey point is deterministic: it takes effect on the chunk immediately after the 0x23 frame
   in each direction, so both sides advance at the same stream position.
```

When to use: on a counter, for example every `REKEY_MESSAGES` (default 10000) chunks or every
`REKEY_SECONDS` (default 900 s) per direction, whichever comes first.

### 5.6.2 Full rekey (fresh ephemeral exchange)

The strong path runs a fresh ephemeral X25519 exchange and derives a new `RK`, giving forward secrecy
against an adversary who compromised the current directional keys. It is a compact re-run of 5.3.2
using new ephemerals on both sides.

```
1. initiator: sxBoxKeypair EK2_A_pub, EK2_A_sec
   initiator -> peer: 0x23 body = bencode({ v:1, t:0x23, r:"f", ek: EK2_A_pub,
                                            g: sxSignDetached(bencode(dict without g), IK_A_sec) })
2. responder: verify g against the peer's pinned IK. sxBoxKeypair EK2_B_pub, EK2_B_sec.
   responder -> initiator: 0x23 body = bencode({ v:1, t:0x23, r:"f", ek: EK2_B_pub,
                                            g: sxSignDetached(bencode(dict without g), IK_B_sec) })
3. both: DHnew = kx(EK2_own, EK2_peer)   (one crypto_kx over the two fresh ephemerals)
         RK'   = sxKdfDerive(sxHash(RK || DHnew, 32), "0", "rp-sess0", 32)
         k_tx', k_rx' = sxKdfDerive(RK', "0"/"1", "rp-txrx0", 32)   (directional orientation as 5.3.2)
   The old RK is mixed in so the new root depends on the whole session history (a ratchet step), and
   DHnew injects fresh entropy that a holder of the old keys does not have.
4. both: re-init both secretstream directions under the new k_tx'/k_rx' and exchange fresh headers as
   in steps 6-9 of 5.3.3 (two 0x21-style header frames, or 0x23 frames carrying hd), then resume
   0x22 data. Zero EK2 secrets after use.
```

When to use: on a schedule (default every `REKEY_HARD_SECONDS`, 3600 s), on an explicit user
"re-secure" action, or after any suspected exposure. A full rekey heals the session: even if the
directional keys leaked, traffic after the full rekey is secret again (post-compromise security),
which the light rekey does not provide.

### 5.6.3 Rekey rules

- Either peer MAY initiate a rekey; if both initiate at once, the peer with the lexicographically
  smaller `IK` wins and the other's in-flight rekey is treated as an ack (deterministic tie-break,
  same rule as 5.3.2).
- A rekey MUST NOT be accepted from an unauthenticated frame: the full-rekey frames carry `g`; the
  light-rekey frame is accepted only on an already-established, authenticated stream (it arrives
  inside the authenticated `rp1` message flow and its effect is symmetric, so a forged one simply
  desynchronizes and the next `0x22` fails to pull, tearing the connection down, 3.10).
- During a rekey the connection is in state `rekeying` (section 6); data frames continue under the
  old keys until the rekey point, then under the new keys.

## 5.7 COVER-SEED mode (C3): the deniable session

Cover-seed is the strongest-deniability variant (brainstorm C3, tier 3, threat-model G6). Instead of
meeting at a derived phantom DHT id, both peers **genuinely seed a real, lawful torrent** (for
example a current Linux distribution ISO), join its ordinary swarm, and recognize each other inside
the normal BEP10 extended handshake. The conversation then rides the same peer connection as `rp1`
messages, tunneled inside a connection that is, in every externally observable respect, ordinary file
sharing. There are **no magic bytes**: nothing on the wire says "Riptide" (3.8), so there is no
fingerprint to match.

### 5.7.1 The cover torrent

Both peers agree out of band (at the same time they exchange identity keys, 2.5) on:

- a **cover infohash** `H_cover`: a real, popular, lawful torrent both will seed. Popular and lawful
  matters: popular gives a large anonymity set to hide in, lawful keeps the cover itself defensible
  (responsible-design note in [../brainstorm.md](../brainstorm.md) section 9, and doc 10).
- the shared **recognition secret** `RS` (32 bytes), which is either a pairwise secret they already
  hold (from a prior session or mailbox exchange) or one derived from their identity keys via a
  first-contact handshake. `RS` is the input that lets them build unlinkable per-epoch tokens.

Both peers `PW`-participate in `H_cover`'s swarm as normal seeders, uploading real pieces. This is
the deniability foundation: the traffic is not merely disguised as file sharing, it **is** file
sharing (principle 6).

### 5.7.2 The per-epoch recognition token

A peer signals "I am your Riptide contact" by placing a token in its BEP10 extended-handshake
dictionary, in a field where a benign client-metadata string would sit (for example a `v`
client-version-style key), so its presence is not itself anomalous. The token must be **unlinkable
across epochs**: an observer who logs the swarm's handshakes over days must not be able to say "this
peer on Monday is the same contact as that peer on Tuesday." Both requirements are met by deriving the
token from `RS` and the epoch and signing it:

```
epoch  = floor(unixTime / EPOCH_SECONDS)          -- 3.9; cover-seed MAY use a coarser EPOCH_SECONDS
tokenId = sxHash(RS || be64(epoch) || H_cover || "rp-cvrsd", 20)
   -- a per-epoch, per-torrent tag that only a holder of RS can compute (domain-separated by a
   -- literal tag, exactly like the inbox-id derivation pattern of 3.4).
tokPub  = the ed25519 public key each peer will use to sign under (see 5.7.3 on which key)
sig     = sxSignDetached(tokenId, IK_signing_sec)
token   = bencode({ i: tokenId, s: sig })         -- placed in the extended handshake
```

Because `tokenId` folds in `RS` (a shared secret), only the intended contact can produce or recognize
it; to everyone else it is a random 20-byte blob in a field that often holds opaque bytes. Because it
folds in `epoch`, it changes every epoch, so two epochs' tokens are unlinkable without `RS` (the
`sxHash` output of a fresh epoch is uncorrelated). Rotating the token per epoch is the C3 limit
"recognition tokens must be unlinkable across sessions, derive per-epoch" (brainstorm C3), satisfied
by construction.

### 5.7.3 Recognition and identity binding

The signature is what proves the token came from the specific contact and not from someone who merely
guessed or replayed `tokenId`. Which key signs is a deliberate trade:

- **Recognition-key mode (more deniable):** derive a per-epoch signing keypair from `RS` and the
  epoch (a dedicated ed25519 seed via `sxKdfDerive` under the proposed `rp-cvsig` context, the open
  registry item at the top of this document, added to 3.4 when this mode is implemented), so the
  public key in the token is not the peer's stable identity key. An observer
  cannot link the token to a known identity even if they later learn that identity's `IK`. The
  contact verifies with `sxSignVerifyDetached(s, i, epochPub)`, deriving `epochPub` from the shared
  `RS`. This is the default for cover-seed, because putting the stable `IK_pub` on the wire would
  defeat the unlinkability that the whole mode exists to provide.
- **Identity-key mode (simpler, less deniable):** sign `tokenId` with the stable `IK_sec` and verify
  with the known `IK_pub`. Only use this when the peers accept that a swarm observer who already knows
  their `IK_pub` could confirm their presence; it is not recommended for the threat model cover-seed
  targets.

Recognition flow, on each new peer that joins the cover swarm:

```
1. PW.onConnect(H_cover, peer):
      d = PW.handshakeDict(peer)                 -- that peer's BEP10 extended handshake
2. extract the candidate token from the agreed field of d; if absent, this is an ordinary seeder,
   ignore (just seed to them normally). No token, no anomaly: most peers have none.
3. compute this epoch's expected tokenId from RS (5.7.2). Compare d's tokenId to the expected value
   with sxMemEqual (constant time, 3.3); on mismatch, ordinary seeder, ignore. Also check epoch-1
   and epoch+1 for drift (3.9).
4. on tokenId match: verify the signature s with sxSignVerifyDetached against epochPub (or IK_pub in
   identity-key mode). A match with a bad signature is treated as an ordinary seeder and ignored
   (fail closed, 3.10): it could be an adversary who somehow learned tokenId but cannot forge the
   signature.
5. on a verified token: MUTUAL RECOGNITION. Run the 5.3 handshake over rp1 on THIS peer connection
   (both sides already advertised rp1 in the same extended handshake), then tunnel the secretstream
   session (5.4) as 0x22 frames interleaved with genuine piece traffic.
```

Recognition is mutual: each peer places its own token and checks the other's, so both must present a
valid per-epoch token before either treats the connection as a Riptide session. A one-sided token
does not open a session.

### 5.7.4 Tunneling the session inside the cover connection

After recognition, the session is exactly the session of 5.3-5.6: the same `rp1` subtypes `0x20`,
`0x21`, `0x22`, `0x23`, the same secretstream, the same rekey. The only difference from the phantom
variant (5.2) is that the `rp1` messages are interleaved with real BitTorrent piece messages on a
connection that is genuinely transferring the cover torrent. To keep the cover honest:

- Both peers **continue to serve real pieces** for the whole session, so upload/download counters and
  piece-request patterns look like ordinary seeding (an idle "seeder" that transfers nothing while
  exchanging steady small messages is itself a tell).
- Session frames SHOULD be paced and padded (the 1024-byte bucket of 5.4.1, plus optional cover
  keepalives, 5.4.3) so that the added `rp1` volume blends into the variance of normal peer-wire
  chatter rather than forming a distinct constant-rate flow.

### 5.7.5 The deniability argument and its limits

**What cover-seed buys (G6, against rungs 1, 2, 4).** To a passive network tap (rung 1), a
platform/ISP censor (rung 2), and even a swarm insider who joins the same swarm (rung 4), the
connection is two clients sharing a popular lawful torrent, which is exactly what it also is. The
recognition token sits where opaque client metadata normally sits and is, without `RS`, an
indistinguishable random blob that rotates every epoch; there is no `rp1`-specific magic string to
match (3.8). Both peers can truthfully say "I was seeding Ubuntu," and the claim is not a cover story
but a fact. This is deniability by legitimacy (principle 6): the safest traffic is traffic that is
what it appears to be.

**Where it weakens.** The honest limits (stated per principle 5, threat-model N2/N3):

- **A tracker-running or swarm-running adversary** sees that these two specific IPs are in the swarm
  and, if it does **fine-grained traffic analysis** of the peer connection, may notice that the
  volume, timing, or burst pattern of this pair's connection differs from a pure seeding connection
  (an interactive chat has a request/response rhythm that bulk seeding does not). Cover-seed raises
  the cost of this analysis (real pieces flow, frames are padded and paced) but does not defeat a
  determined rung-4/rung-5 correlator. This is exactly the open question in
  [../brainstorm.md](../brainstorm.md) section 11 ("can C3 survive an adversary who runs the tracker
  and does fine-grained traffic analysis"), and it is not resolved here: cover-seed is a strong
  deniability improvement, not a proof against traffic confirmation (N3).
- **Contentless behavior is a tell.** If a "seeder" never actually uploads or downloads, the cover is
  hollow; 5.7.4 requires genuine seeding precisely to avoid this. A peer that connects, exchanges
  small messages, and transfers no pieces is more suspicious than an ordinary phantom-swarm peer, not
  less.
- **IP is still exposed (N1).** Cover-seed hides the *existence and content* of the conversation, not
  the fact that these two IPs are peers in a public swarm. An adversary who can map an IP to a person
  (rungs 3-4) still learns that two people are in the same swarm; to hide that, run the whole stack
  over Tor/I2P or the multi-hop extension (N1, doc 10). Cover-seed and IP anonymity are orthogonal
  layers.
- **The anonymity set is the swarm.** Deniability is only as strong as the crowd: a large popular
  torrent gives many innocent peers to hide among; a tiny or unusual torrent gives few, and a swarm
  of size two is no cover at all. Choose a genuinely popular cover (5.7.1).

## 5.8 Connection state machine

A `rp1` connection (phantom or cover-seed) moves through these states. The same machine governs both
variants; only how `idle -> handshaking` is entered differs (rendezvous by derived id, versus mutual
token recognition in a cover swarm).

```
        rendezvous / recognition           handshake 0x20/0x21 completes,
        connection open, rp1 advertised     ac verified, headers exchanged
  idle ------------------------------> handshaking ------------------------------> established
    ^                                      |                                          |   ^
    |                                      | any verify/auth failure (3.10)           |   | rekey
    |                                      | epoch out of window, bad sig, bad ac     |   | complete
    |                                      v                                          v   |
    |                                    closed <----------------------------- rekeying --+
    |                                      ^        FINAL tags both directions,       |
    |                                      |        pull failure, or timeout          |
    +--------------------------------------+---------------------------------------------+
       (session over; handles freed; may re-enter idle for a new session)
```

State semantics:

| State | Meaning | Entry | Exit |
|---|---|---|---|
| `idle` | no session; peer maybe connected and seeding (cover-seed) but no Riptide session | start; after `closed` | on rendezvous match (5.2) or verified token (5.7.3) -> `handshaking` |
| `handshaking` | running 5.3; keys not yet confirmed | connection open, initiator sends 0x20 | on step 7-9 success -> `established`; on any auth/epoch/sig failure -> `closed` (3.10) |
| `established` | live session; 0x22 data flows; keepalives run (5.4.3) | handshake complete | on rekey trigger -> `rekeying`; on close/timeout/pull-failure -> `closed` |
| `rekeying` | running 5.6; data continues under old keys until the rekey point | rekey initiated (5.6.3) | on rekey complete -> `established`; on failure -> `closed` |
| `closed` | session ended; both stream handles freed (`sxFreeStream`), ephemerals zeroed | FINAL both directions (5.5), pull failure (3.10), or timeout (5.4.3) | may re-enter `idle` for a new session on the same or a new connection |

Any authentication or decryption failure in any state transitions directly to `closed` and tears down
the session (fail closed, 3.10). There is no error state that keeps a half-authenticated session
alive.

## 5.9 Security properties

Mapped to the goals G1-G7 and non-goals N1-N7 of [01-threat-model.md](01-threat-model.md) and the
adversary rungs 1-5.

| Property | Rungs | How the session provides it |
|---|---|---|
| **G1 Confidentiality** | 1-4 | All data is secretstream (XChaCha20-Poly1305) under keys only the two peers derive (5.3, 5.4). Handshake control fields carry no plaintext content. |
| **G2 Integrity / authenticity** | 1-4 | Every `0x22` chunk carries a Poly1305 tag; a bad pull fails closed (5.4.2). Handshake init/resp are ed25519-signed (`g`) and key-confirmed (`ac`) (5.3.4). |
| **G3 Forward secrecy** | 1-4 | Ephemeral `EK_A` (and `OPK_B`) are deleted after the handshake, so a later identity-key compromise does not decrypt this session (5.3). Secretstream forgets past chunk keys; light rekey (5.6.1) and full rekey (5.6.2) advance key material. **Full rekey adds post-compromise security**: traffic after a full rekey is secret again even if directional keys leaked (5.6.2). |
| **G4 Replay / reorder resistance** | 1-4 | Secretstream's internal per-chunk chaining rejects any injected, dropped, duplicated, or reordered `0x22` frame (5.4.2). The handshake binds `epoch` and consumes one-time prekeys, so a captured init is not replayable (5.3.5). |
| **G5 Censorship resistance** | 2, (3 with effort) | No server and no fixed rendezvous: phantom ids rotate per epoch (5.2, doc 04); cover-seed hides in a real swarm (5.7). A Sybil eclipsing one rendezvous id is countered by rotation and by falling back to cover-seed. |
| **G6 Deniability** | 1, 2, 4 (cover-seed only) | Cover-seed carries the session inside a genuine lawful torrent transfer with no magic bytes and per-epoch unlinkable tokens (5.7). Not claimed against fine-grained traffic analysis by a tracker-running rung-4/5 adversary (5.7.5). The phantom variant (5.2) is only tier-2 deniable ("some swarm"), not tier-3. |
| **G7 Sender anonymity** | n/a here | A session is mutually authenticated by design (5.3.4); it does not aim to hide the sender from the recipient. Sealed-sender anonymity is the mailbox's property ([06-mailbox.md](06-mailbox.md)), not the session's. |

Non-goals that apply, stated plainly (principle 5):

- **N1 No IP anonymity.** Both variants expose each peer's IP to the other and, in the swarm, to
  every other peer and to the DHT. Cover-seed hides the conversation, **not** that two IPs are peers
  in a public swarm (5.7.5). For IP privacy, run over Tor/I2P or the multi-hop extension (doc 10).
  This is the single most important limit of the live session and is repeated here per principle 5.
- **N2 Incomplete metadata privacy.** A rung-3 DHT crawler can see that a phantom rendezvous id is
  active and who queries it (mitigated by per-epoch rotation, doc 04, not eliminated). Cover-seed
  moves the metadata into a public swarm's peer list, which is also observable.
- **N3 No defense against a global passive correlator (rung 5).** Cover-seed and multi-hop only
  approximate this; a fine-grained traffic-analysis adversary is not defeated (5.7.5).
- **N6 Endpoint security assumed.** Directional keys and stream handles live in script-managed
  memory that SodiumXT cannot lock or wipe; a compromised endpoint exposes the live session's keys
  (threat-model N6, and the SodiumXT honesty rule).
- **N7 Availability is best-effort.** Both peers must be online (5.1); a dropped connection or a dead
  swarm ends the session, to be retried, never worked around by an unauthenticated fallback (3.10).

Trade named per principle 5: cover-seed trades **throughput** (session bandwidth competes with real
seeding, brainstorm C3) for **deniability** (G6). The phantom variant trades that deniability back
for throughput and simpler rendezvous. Choose the variant by which the deployment's target rung
demands (threat-model, "how to read the rest of the spec against this model").
