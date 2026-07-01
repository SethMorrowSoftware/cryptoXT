# 00. Architecture and principles

## The layer cake

Riptide is defined as five layers. Each layer depends only on the ones below it, so a channel can
be described as a choice of options at each layer.

```
+-----------------------------------------------------------------------+
| L4  Channels    mailbox | session | feed | groups | objects           |  what the user sees
+-----------------------------------------------------------------------+
| L3  Envelopes   sealed / boxed / AEAD frames; padding; replay binding  |  the message format
+-----------------------------------------------------------------------+
| L2  Sessions    handshake, ratchet, secretstream; sender keys          |  key agreement over time
+-----------------------------------------------------------------------+
| L1  Carriers    BEP44 records | BEP10 ext-messages | encrypted torrents |  how bytes move on BitTorrent
+-----------------------------------------------------------------------+
| L0  Identity + rendezvous   ed25519/X25519 keys; derived DHT ids        |  who you are, where you meet
+-----------------------------------------------------------------------+
```

- **L0 Identity + rendezvous** ([02-identity.md](02-identity.md), [04-rendezvous.md](04-rendezvous.md)):
  a single master seed yields your signing (ed25519) and encryption (X25519 / kx) keys. Meeting
  points are 20-byte DHT ids derived from shared secrets and rotating epochs.
- **L1 Carriers** ([03-conventions.md](03-conventions.md), [09-objects.md](09-objects.md)): three
  ways to move bytes: a BEP44 DHT record (signed, ~1000 bytes, for mailboxes and feeds), a BEP10
  peer-wire extension message (arbitrary size, for live sessions), or an encrypted torrent (bulk).
- **L2 Sessions** ([05-session.md](05-session.md), [06-mailbox.md](06-mailbox.md)): turn a first
  contact into an ongoing keyed relationship: the handshake, the message ratchet, secretstream for
  live streams, and per-member sender keys for groups.
- **L3 Envelopes** ([03-conventions.md](03-conventions.md)): the byte format of a single protected
  message: which SodiumXT primitive sealed it, the padding, and the associated data that binds it to
  its epoch and sequence to stop replay and reordering.
- **L4 Channels** (docs 06-09): the user-facing shapes: async mailbox, live session, broadcast feed,
  group room, shareable object.

## Design principles

1. **The easy way is the safe way.** Riptide inherits SodiumXT's misuse resistance. Callers never
   choose a nonce, never pick a cipher, and never compare a secret with `is`. Every message is
   authenticated encryption; there is no unauthenticated mode.
2. **One identity, everywhere.** The same ed25519 key names you in the DHT, signs your BEP44
   records, and anchors your encryption keys. Losing it is losing your identity; backing it up is
   backing up everything. Key management is therefore a first-class concern, not a footnote.
3. **The network is the server.** There is no Riptide server. The DHT is the directory and the
   message queue; the swarm is the content-distribution network; the peer wire is the socket.
4. **Rotate by default.** Rendezvous ids, prekeys, session keys, and recognition tokens all rotate
   on an epoch clock so that a passive DHT crawler cannot link two epochs of the same relationship.
5. **Say what you cannot protect.** Riptide is loud about the metadata and IP-anonymity it does not
   provide (see [01-threat-model.md](01-threat-model.md)). A security tool that overstates its
   guarantees is worse than one that is honest about them.
6. **Deniability through legitimacy.** The strongest privacy mode (cover-seed,
   [05-session.md](05-session.md)) hides a conversation inside a real, lawful BitTorrent transfer,
   so the safest traffic is traffic that looks exactly like what it is not.
7. **Consent, not reach.** Channels default to accepted contacts and verified keys. Open,
   world-writable inboxes are gated by anti-abuse mechanisms ([10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md)),
   not left open.

## How a message flows (the mailbox example, end to end)

A one-screen tour of the layers working together for an asynchronous message. Details and exact
calls are in the referenced docs.

```
1. Bob publishes a signed prekey bundle as a BEP44 mutable record under his identity key.   (L0/L1)
2. Alice fetches it, verifies Bob's signature, and runs the handshake to agree a chain key.  (L2)
3. Alice derives this message's key from the chain key and the message counter (the ratchet). (L2)
4. Alice builds an envelope: pad the plaintext, seal it, bind the epoch+counter as AD.         (L3)
5. Alice writes the envelope as a BEP44 record at Bob's derived inbox id for that counter.      (L1)
6. Bob scans his inbox counters, opens the envelope, and ratchets his chain key forward.        (L2)
```

No server saw the message. The DHT saw a signed ~1 KB blob at an unlinkable key. Bob's reply
reverses the flow.

## Channel summary

| Channel | Doc | Shape | Primary use |
|---|---|---|---|
| Mailbox | [06](06-mailbox.md) | async 1:1 | offline messaging |
| Session | [05](05-session.md) | live 1:1 | real-time chat / signaling / voice keying |
| Cover-seed session | [05](05-session.md) | live 1:1, max deniability | conversation hidden in a real swarm |
| Feed | [07](07-feed.md) | async 1:many | encrypted broadcast / private channel |
| Public wall | [07](07-feed.md) | async 1:many, public | signed, un-deplatformable publishing |
| Group room | [08](08-groups.md) | N:N | small encrypted groups |
| Object / link | [09](09-objects.md) | async, by possession | encrypted shareable files and links |

Everything above is the same identity and the same conventions, recombined.
