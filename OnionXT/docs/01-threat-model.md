# 01 - Threat Model

OnionXT exists to close the metadata gap the family's other transports leave open. This document is
the honest account of what routing through Tor with onion-service rendezvous actually buys, what it
does not, and the rules that keep the docs and the UI from overpromising.

## What OnionXT is for

Riptide's own threat model lists, as **unsolved** open items, "no IP anonymity by default" and
"incomplete metadata privacy" (its rung-4 adversary: one who watches the network layer and correlates
who talks to whom). OnionXT is the direct answer to that adversary at the IP layer:

- **IP anonymity.** With SOCKS5 dialing, the far end never learns the initiator's IP. With an onion
  service, neither end learns the other's IP, and there is no exit node in the path (the circuit stays
  inside Tor end to end).
- **No rendezvous metadata leak.** Swapping DHT rendezvous for an onion address removes the DHT
  lookups and direct peer connections that leak the initiator's IP and the fact of contact to anyone
  watching the DHT or the peer's link.
- **Self-authenticating naming.** The onion address is the contact's ed25519 public key, so first
  contact does not require a separate, MITM-able key-distribution channel.

## The adversary ladder (aligned with Riptide's)

- **Rung 1 (a co-subscriber / passive peer):** sees only onion-routed ciphertext. Learns nothing.
- **Rung 2 (the app's ISP / local network):** sees that the app talks to the Tor network (a known set
  of guard IPs) and the volume/timing of that traffic. Does **not** see the destination, the `.onion`,
  or the payload. Tor's guards and (optionally) pluggable transports address "sees you use Tor."
- **Rung 3 (an active network attacker who controls the rendezvous path):** cannot MITM a v3 onion,
  because connecting to it authenticates the far end's ed25519 key. Can deny service (block Tor, drop
  circuits) but cannot silently impersonate, provided the app pins or verifies the address.
- **Rung 4 (a global passive adversary doing traffic correlation):** can, in principle, correlate the
  timing and volume of traffic entering and leaving Tor to link the two ends. Tor does not defend
  against this, and neither does OnionXT. This is the honest ceiling.

## What Tor + OnionXT do NOT protect

Ship these labeled for exactly what they are; do not let the UI imply otherwise.

1. **Traffic-correlation / global passive adversary.** Out of scope, as for Tor itself. Padding and
   cover traffic (see Riptide's playbook and `sxPad`) raise the cost but do not close it.
2. **A compromised local tor daemon.** OnionXT trusts the daemon on loopback. That daemon sees your
   SOCKS targets, and if it generates your onion key it sees that key. A malicious or subverted local
   Tor is game over. Mitigate by deriving onion keys yourself from a SodiumXT seed and passing them in
   (doc 04), so at least the identity key never originates in the daemon, and by trusting only a daemon
   you control.
3. **Endpoint compromise.** If the app's device is compromised, anonymity is moot. Out of scope.
4. **Connecting to the wrong onion.** The address authenticates the key, not the person. If an attacker
   convinces you to use *their* `.onion`, Tor faithfully connects you to the attacker. Address
   verification / pinning (or binding the address into a SodiumXT signature at first contact) is the
   app's responsibility, exactly as Riptide verifies keys at first contact.
5. **Descriptor and timing metadata.** Publishing an onion descriptor reveals timing to the hash-ring
   directories; connection timing reveals when you are online. Onion services reduce, but do not
   eliminate, "when is this identity active" metadata.
6. **Payload confidentiality and integrity.** OnionXT does not encrypt anything. The bytes it carries
   are protected only if the app sealed them with SodiumXT. Tor's onion layers protect the *path*, not
   an application-level "the recipient is who I think and the message is intact" property; that is
   SodiumXT's job, and it must be done.
7. **Bootstrapping and availability.** Tor can be blocked, slow to bootstrap, or unavailable. OnionXT
   is not a censorship-circumvention guarantee; it is an anonymity layer that assumes Tor is reachable.

## The trust boundaries, stated plainly

- **Trusted:** the local tor daemon (on loopback), the app process, the SodiumXT crypto.
- **Untrusted:** the entire network beyond the daemon, any peer until its onion address is verified,
  the DHT/directory infrastructure, and any relay.
- **The onion address is identity.** Treat a contact's `.onion` as their public key: pin it, and bind
  it to a SodiumXT signature when you can, so a swapped address is detected.

## The honesty rules (carried from the family)

- Never present an open problem as solved. Traffic correlation, local-daemon trust, and descriptor
  metadata are tracked in [09-open-questions.md](09-open-questions.md); ship them labeled.
- State the non-goals to the user in plain language, not buried in a spec.
- "Anonymous" in the UI means "IP-anonymous against a non-global adversary via Tor," not "untraceable."
  Say the honest version.
