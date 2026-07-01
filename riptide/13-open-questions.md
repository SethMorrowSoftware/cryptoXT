# 13. Open questions

This document is the research agenda: the design forks Riptide has not resolved and the research
problems it has not solved. Everything here is deliberately unfinished. The foundation documents
(00-overview.md, 01-threat-model.md, 03-conventions.md) and the identity document (02-identity.md)
make honest promises precisely because the harder claims are quarantined here instead of asserted
prematurely.

Each question is stated with four parts so someone can pick it up cold:

- **Question:** the fork or problem, precisely.
- **Why it matters:** what breaks or stays weak until it is answered.
- **Current best guess:** the partial approach the spec leans on today, and why it is not yet an
  answer.
- **What a good answer looks like:** the artifact (a number, a proof, a protocol, a measurement)
  that would close it.

Two tags on each:

- **Difficulty:** rough effort. `low` (a focused study or a well-scoped mechanism), `medium` (a
  real research or engineering project), `high` (an open problem, possibly a thesis, possibly no
  clean answer exists).
- **Gating:** `blocks-v1` (a minimum viable Riptide should not ship without at least a stated,
  defensible position here), or `later` (v1 can ship with the honest limit stated in
  01-threat-model.md and this question deferred).

The questions are grouped: privacy and metadata, crypto and protocol, systems and reliability, and
governance and assurance. A short reading at the end names the one or two that most gate a real
deployment.

---

## A. Privacy and metadata

These are the questions behind non-goals N1, N2, and N3 in 01-threat-model.md, and the "part"
cells in the brainstorm security matrix that the whole project wants to turn into "strong."

### A1. Metadata privacy, quantified, against a rung-3 DHT crawler

**Question.** How much do the three metadata defenses actually buy, measured, against the rung-3
adversary of 01-threat-model.md (an active DHT participant / Sybil that crawls the keyspace and can
target a key)? The three defenses are (1) rotating derived ids on the epoch clock (03-conventions.md
3.9, principle 4 in 00-overview.md), (2) k-anonymous inbox buckets (the bucket-prefix addressing
sketched for the mailbox in 06-mailbox.md and section 5 of brainstorm.md), and (3) cover traffic
(decoy announces and decoy cell writes). Concretely: given an adversary running `M` DHT nodes out of
a network of `N`, with an epoch length `E` and a per-relationship activity rate `r`, what is the
probability it can (a) link two epochs of the same channel, (b) confirm that a specific pair of
identities communicates, and (c) enumerate the set of active Riptide ids? And what is the
anonymity-set size `k` and cover-traffic rate that pushes each of those below a target?

**Why it matters.** N2 currently says only "raises the cost ... does not eliminate it." That is
honest but unusable for a deployment decision: a user in a hostile jurisdiction needs to know
whether the residual linkage probability is 1-in-10 or 1-in-10^6, and an operator needs to know the
bandwidth cost of getting there. Without numbers, the k-anonymity and cover-traffic mechanisms are
faith, not engineering, and the epoch length `EPOCH_SECONDS` (03-conventions.md 3.9) is a magic
constant (3600) with no derivation.

**Current best guess.** Rotation bounds linkage to within one epoch, so shorter epochs are safer
against linkage but cost more re-puts (couples directly to C1/BEP44 republication, question C1
below) and more adjacent-epoch checks (3.9 says check `epoch-1` and `epoch+1`, which triples a
crawler's observable footprint per lookup). k-anonymity hides which recipient inside a bucket of `k`
you wrote to, but the bucket itself is observable and its population is not uniform. Cover traffic is
assumed to be cheap and effective; neither is established. The mainline DHT is roughly 10^7 nodes,
which sets the Sybil fraction a realistic adversary can buy, but we have not modeled how few nodes
near a target id suffice to log all gets (the eclipse literature suggests it is alarmingly few, on
the order of the replication factor, 8-20 nodes).

**What a good answer looks like.** A quantitative model, ideally validated by a measurement study
against a private DHT (or a careful, ethical observation of the mainline DHT's churn baseline), that
outputs the three probabilities as functions of `(M/N, E, r, k, cover-rate)` and identifies the
Pareto frontier of anonymity-set size versus bandwidth. The deliverable that would actually change
the spec: a recommended `(EPOCH_SECONDS, k, cover-rate)` operating point per adversary rung, with
its residual linkage probability stated, replacing the current hand-waved 3600.

**Difficulty:** high. **Gating:** blocks-v1 for the metadata-privacy claim specifically. v1 can ship
the channels without the quantification if N2's honesty holds, but the project cannot claim
"metadata privacy" as a feature until this exists. Ship v1 with the limit stated; treat the number
as a fast-follow that gates any marketing of metadata protection.

### A2. Does cover-seed deniability survive a tracker-running, traffic-analyzing adversary?

**Question.** The cover-seed mode (C3 in brainstorm.md, defined in 05-session.md) hides a
conversation inside a real, lawful BitTorrent transfer, and claims tier-3 deniability and even some
resistance to the rung-5 global observer (G6 in 01-threat-model.md lists it against rungs 1, 2, 4).
Does that deniability actually survive an adversary who runs the tracker for the cover torrent (so
it sees the full peer set and every announce) AND performs fine-grained traffic analysis on the
specific peer connection (packet sizes, inter-packet timing, the ratio of "useful" piece traffic to
total)? A genuine Ubuntu seed has a characteristic traffic shape; a connection that also carries an
interactive chat has a different one (bursts on keystrokes, request/response latencies, a
piece-request pattern that does not match real download progress).

**Why it matters.** Cover-seed is called "the most interesting corner in the whole document"
(brainstorm C3) and is the only mode that even approaches rung-5. If a tracker operator plus a tap
can distinguish a cover-seed connection from a real one by traffic shape, the headline deniability
property collapses to "looks like BitTorrent to someone not looking hard," which is a much weaker and
more honest claim. The extension handshake already avoids a magic string to dodge a static
fingerprint (03-conventions.md 3.8), but timing and volume are a dynamic fingerprint that
handshake-hygiene does not touch.

**Current best guess.** 05-session.md carries the conversation as BEP10 extension messages on a
connection that also serves real pieces, so the bytes are there under cover of real traffic. The
unexamined part is the *shape*. The likely mitigation is a traffic-shaping / constant-rate padding
scheme on the extension-message channel so the tunnel's contribution is a smooth, torrent-like
envelope rather than an interactive burst pattern, at the cost of latency and wasted bandwidth (the
classic anonymity-vs-performance trade, and the same trade as A1's cover traffic). It is not
specified, and it fights the "capacity competes with real seeding" limit already noted in C3.

**What a good answer looks like.** A traffic-analysis study: collect real seed-connection traces and
cover-seed traces, run a classifier, and report the distinguishing accuracy with and without a
padding/shaping defense. A good answer states the shaping regime (constant-rate? Poisson cover?
buckets?) that drops the classifier to near chance, and its concrete latency and bandwidth cost, so
05-session.md can either specify it or downgrade G6's rung claims to match reality.

**Difficulty:** high. **Gating:** blocks-v1 for the deniability claim (G6). The cover-seed channel
can ship as "tier-2 unattributed, tier-3 aspirational" without it, but must not be sold as tier-3
deniable until the traffic-shape question is answered. Downgrade the claim now; upgrade it when
measured.

### A3. Cover-traffic economics and the shared cost model

**Question.** Cover traffic appears in three places (A1's decoy cells and announces, A2's connection
padding, and the presence beacons of C7 in 07-... / rendezvous). What is the actual bandwidth,
battery, and DHT-load cost of a cover-traffic regime strong enough to matter, and who pays it? Is
there a cover-traffic design that is cheap enough that always-on clients can afford it, or does
effective cover require a rate that only a desktop-on-mains can sustain (leaving mobile users with
weaker anonymity, a fingerprint in itself)?

**Why it matters.** A defense nobody can afford to run is a defense nobody runs. If effective cover
costs more than users tolerate, the k-anonymity set collapses to the few who pay, which is worse than
no cover because it marks them. This is the operating-point question of A1 seen from the client-cost
side.

**Current best guess.** Section 5 of brainstorm.md calls cover traffic "cheap," which is asserted,
not shown. The performance playbook in CLAUDE.md (single-threaded, payload crosses the FFI) means
cover work competes with real work on one interpreted thread, so "cheap" has an OXT-specific ceiling.

**What a good answer looks like.** A cost model tied to A1's benefit model, yielding a
cost-per-unit-anonymity curve, plus a device-class recommendation (what cover rate is sane on
mobile vs desktop) and an explicit statement of the fingerprint created by heterogeneous cover
rates.

**Difficulty:** medium. **Gating:** later (couples to A1; can be answered alongside it).

---

## B. Crypto and protocol

### B1. Group forward secrecy without a server: how far do sender keys go, and can MLS run over the DHT?

**Question.** Two-part. (1) How far does the `sxKdfDerive` sender-key scheme for group rooms
(context `rp-sendr`, 03-conventions.md 3.4; C5 in brainstorm.md; 08-groups.md) actually get before
it needs replacing? Sender keys give per-sender authentication and cheap add, but removing a member
or achieving post-compromise security requires re-deriving the room key and redistributing sender
keys to everyone, which is O(N) per change and gives no forward secrecy within a static room key.
What is the group size and churn rate past which this is untenable? (2) If the answer is "you need a
tree" (MLS-style continuous group key agreement), can an MLS-like tree ratchet run over Riptide's
carriers, a DHT that is ~1000-byte records with best-effort availability and a swarm gossip bus, with
no server to order and fan out the key-package and commit messages that MLS assumes?

**Why it matters.** 01-threat-model.md G3 already carves groups out of the forward-secrecy guarantee
("Feeds and static objects provide this only via key rotation"), and brainstorm section 8 flags this
as an MLS-class problem. Groups are a headline channel (C5); if they cannot get forward secrecy or
efficient revocation, that limit must be stated as sharply as the mailbox's strengths, and the fork
between "stay with sender keys, small static rooms" and "port MLS to the DHT" must be chosen
deliberately, not by drift.

**Current best guess.** 08-groups.md starts with static small rooms and sender keys, exactly as
brainstorm C5 recommends ("start static and small, graduate to a tree-based ratchet later"). The open
part is the graduation. MLS assumes a Delivery Service that provides a consistent, ordered fan-out of
handshake messages; Riptide has no such service. The DHT gives a signed, seq-ordered per-key log
(the same mechanism as the identity log, 02-identity.md 2.6) which could carry commits, but its
~1000-byte budget (03-conventions.md 3.5.2) is hostile to MLS key-packages, and its availability is
best-effort (N7), so the "everyone applies the same commit in the same order" invariant MLS needs is
not free. The likely middle path is a bounded-size group with an epoch-based full rekey (rotate the
room key each epoch via `rp-sendr`, accept no intra-epoch forward secrecy) rather than a true tree.

**What a good answer looks like.** (1) A concrete threshold: the `(N, churn-rate)` past which flat
sender keys stop being acceptable, with the cost of the alternative. (2) Either a design for
MLS-over-DHT that names how ordering, fan-out, and the size budget are solved (and its availability
assumptions), or a reasoned rejection ("MLS needs a delivery service Riptide structurally lacks;
here is the weaker but serverless scheme we use instead"). Either outcome updates 08-groups.md's
security-properties note.

**Difficulty:** high. **Gating:** later for the tree; blocks-v1 for stating the sender-key limit
sharply. v1 groups can be static and small with the forward-secrecy limit stated; the tree is R&D.

### B2. Key transparency at scale: witnessing and gossiped consistency without a log server

**Question.** The identity log (02-identity.md 2.6) is a hash-chained, ed25519-signed BEP44
seq-chain, and a follower detects a broken `prev` link or a fork at a given `seq`. But a follower
only detects a fork if it *sees both branches*. A rung-3 adversary that eclipses the log key
(01-threat-model.md, "eclipse a DHT key") can show victim A branch-1 and victim B branch-2 forever,
and neither detects the split-view because neither sees the other's branch. Real key-transparency
systems (CT, Keybase, and the transparency literature) close this with witnesses (independent
parties that co-sign the log head they saw) and gossip (clients exchange log heads so a split view is
eventually caught). How do we get witnessing and gossiped consistency with no log server and no fixed
witness set?

**Why it matters.** 02-identity.md is explicit that the self-chained log "does not stop a compromise,
but makes a silent key swap loud," and that a full system (gossiped consistency, witness co-signing)
is deferred here. Key transparency is the *only* defense (besides out-of-band safety numbers) against
a rung-3 MITM at first contact (01-threat-model.md trust assumptions, and the attack-surface row
"MITM at first contact"). If the log is split-view-forgeable, the "detect a later substitution even
if the first fetch was honest" promise of 2.5 is weaker than stated against exactly the adversary it
targets.

**Current best guess.** The buildable baseline is the self-chained log (shipped). A serverless gossip
layer could piggyback log heads on existing contact channels: whenever A and B have any authenticated
Riptide session, they exchange the log heads they hold for their mutual contacts, so a split view is
caught the moment two victims of the same eclipse ever talk to each other. This is opportunistic, not
guaranteed, and its detection latency depends on the social graph's connectivity. A witness set could
be volunteer nodes that co-sign observed heads, but that reintroduces a trusted-party question and a
Sybil surface (who witnesses the witnesses).

**What a good answer looks like.** A serverless consistency protocol with a stated detection
guarantee: "a split view is detected with probability p within time t given social-graph
connectivity c," plus a witness scheme whose trust assumptions and Sybil resistance are spelled out
(or a proof that opportunistic gossip alone suffices for the target threat). Updates 02-identity.md
2.6 from "extension, noted in 13" to a real mechanism.

**Difficulty:** high. **Gating:** later. v1 ships the self-chained log with the split-view limit
stated; gossip/witnessing is the hardening pass. Note the coupling to A1: log gossip is itself
metadata (it reveals who shares contacts).

### B3. Anti-spam for open inboxes: proof-of-work vs capability tokens vs hybrid, and the economics

**Question.** Open, world-writable inboxes (the mailbox at a pubkey-derived id, C1; the mutable-put
gate mentioned in 03-conventions.md 3.7) are a spam and malware-drop magnet with no server to
rate-limit them. Which anti-spam mechanism is cheapest for the honest sender while being expensive
enough for the spammer, and what is its actual economics? Three candidates: (1) proof-of-work bound
to inbox+epoch (a memory-hard puzzle so a phone can afford one message but a spammer cannot afford a
million), (2) capability tokens (a MAC the recipient issued to accepted contacts, checked before the
recipient spends effort trial-decrypting), or (3) a hybrid (PoW for strangers, tokens for known
contacts).

**Why it matters.** 00-overview.md principle 7 ("consent, not reach") and the attack-surface row
"spam an open inbox" already commit Riptide to gating open inboxes, and brainstorm sections 5 and 9
make anti-spam a day-one requirement, not a bolt-on. But the choice is unmade, and the choice has
sharp consequences: PoW taxes honest mobile users and is defeated by an adversary with cheap compute
(the asymmetry may not exist at the needed scale); capability tokens solve spam but *break the open
inbox* (a stranger with no token cannot reach you, which kills the "anyone can send me a first
message" use case that first-contact and the whole prekey-bundle design assume); a hybrid must define
how a legitimate stranger bootstraps a token.

**Current best guess.** The threat model and brainstorm lean toward PoW for the open/stranger path
and tokens for known contacts (the hybrid). The unresolved economics: what PoW cost simultaneously
(a) a phone tolerates for one first-contact message, and (b) prices a spammer out per-inbox-per-epoch,
given that the epoch clock (3.9) resets the puzzle hourly and a botnet has millions of cheap cores.
The memory-hard-vs-compute-hard choice matters because Argon2id (already in the stack, `sxPwHash`) is
memory-hard and available, which biases toward a memory-hard PoW that GPUs and ASICs help less with.

**What a good answer looks like.** A cost analysis in real money: the honest-sender cost (seconds of
phone CPU, joules) versus the spammer cost per thousand delivered messages, for a chosen PoW
parameterization, plus a defined token-issuance flow for legitimate strangers so the hybrid does not
silently become a closed inbox. The deliverable that changes the spec: a recommended gate for the
inbox put in 03-conventions.md 3.7 and 06-mailbox.md, with its parameters and its honest-user tax
stated.

**Difficulty:** medium. **Gating:** blocks-v1. An open inbox with no gate is not shippable (it
becomes a spam sink on first exposure), and the prekey/first-contact design assumes strangers can
reach you, so the gate's shape is on the critical path for the mailbox channel.

### B4. Epoch-clock synchronization without a trusted time source

**Question.** Every rotating identifier depends on `epoch = floor(unixTime / EPOCH_SECONDS)`
(03-conventions.md 3.9). All parties to a channel must agree on the epoch to compute the same
rendezvous id, presence id, or feed key. But there is no trusted time source in a serverless system,
and a device with a wrong clock (drift, a deliberately skewed clock, no NTP behind a censor) computes
the wrong id and silently fails to meet its contact. How much clock skew does the adjacent-epoch check
(3.9 says check `epoch-1`, `epoch`, `epoch+1`) actually tolerate, and what happens at the boundary and
under adversarial time manipulation?

**Why it matters.** A rendezvous that silently fails because two clocks disagree by more than one
epoch is a reliability and usability bug that looks like a censorship success; the user cannot tell
"my contact is offline" from "our clocks disagree." An adversary who can influence a target's clock
(NTP spoofing, or just a jurisdiction that blocks time sync) can force a rendezvous miss without ever
touching the DHT. And the adjacent-epoch check widens the crawler's observable window (couples to A1:
checking three epochs triples the lookups a rung-3 adversary sees).

**Current best guess.** 3.9 mandates the +/-1 adjacent-epoch check, which tolerates up to
`EPOCH_SECONDS` of skew (one hour at the default) minus the phase within the epoch. That is generous
for honest drift but says nothing about deliberate skew, and it trades directly against A1 (more
epochs checked = more metadata leaked). A wider tolerance (check +/-2 or more) buys robustness at
linear metadata cost.

**What a good answer looks like.** A stated skew budget and a robustness analysis: how far can clocks
drift before rendezvous fails, what the adjacent-epoch check costs in crawler-visibility (feeding
A1's model), and whether a lightweight serverless time-agreement (median of a few peers' claimed
times, with a bound on how far an adversarial peer set can drag it) is worth adding versus just
mandating NTP and a wider tolerance.

**Difficulty:** low to medium. **Gating:** blocks-v1 for a stated tolerance (rendezvous must have a
defined skew budget or it will fail mysteriously in the field); the adversarial-time analysis is
later.

### B5. Deniability vs non-repudiation tension in groups

**Question.** The sealed-box mailbox gives sender anonymity and, with it, deniability: a sealed-box
message does not prove who sent it, even to the recipient (01-threat-model.md G7). But group rooms
optionally use `sxSignDetached` for cross-member non-repudiation (C5 in brainstorm.md), which is the
opposite property: a signed group message is provable to third parties, so a member can be shown to
have said something. These are in direct tension, and different users want opposite things (a
whistleblower wants deniability; a group that needs accountability wants attribution). Which is the
default, and can a single group support both without the choice leaking (an unsigned message in a
mostly-signed room is itself a signal)?

**Why it matters.** Getting this wrong is a safety failure in both directions: a user who believes a
group is deniable but whose messages are signed can be incriminated; a group that believes it has
accountability but uses sender keys (MACs, not signatures) has repudiable messages any member could
have forged. 08-groups.md must state which property it provides and must not let the two modes coexist
in a way where the mode choice is a metadata leak.

**Current best guess.** Sender keys (`rp-sendr`, symmetric MACs) give per-sender authentication that
is repudiable (any holder of the sender key could have produced it, so it does not prove authorship to
a third party), which leans deniable-by-default. Optional signing is an explicit opt-in for groups
that want accountability, per member or per message. The unexamined leak: mixing signed and unsigned
messages in one room makes the signed ones stand out.

**What a good answer looks like.** A clear default (likely: repudiable sender keys, deniable by
default, matching the rest of Riptide's posture) and a rule for the signed mode (whole-room, not
per-message, so the choice does not leak), with the property stated in 08-groups.md's
security-properties note and surfaced to the user (the UI must not let someone believe a room is
deniable when it is not).

**Difficulty:** low to medium (mostly a design decision plus a leak analysis, not new crypto).
**Gating:** blocks-v1 for groups (the default must be chosen and stated before groups ship); the
dual-mode leak analysis is a fast-follow.

---

## C. Systems and reliability

### C1. BEP44 republication and availability: how aggressively, and can subscribers share the load?

**Question.** BEP44 records expire and the DHT churns, so records (prekey bundles, mailbox cells, feed
indices, log entries) must be re-put periodically or they vanish (N7; brainstorm section 8, "size and
reliability"). Two parts. (1) How aggressively must a record be re-put to survive with a target
availability, as a function of DHT churn rate and replication factor? (2) For a feed or a widely-read
record, can the *subscribers* share the republication load (each re-puts what it fetched) so the
publisher is not a single point of both work and identification, and can they do so **without
deanonymizing themselves** (a subscriber that re-puts a record is announcing that it reads that
record)?

**Why it matters.** This is the reliability floor for every async channel. Too-infrequent re-puts mean
messages silently expire (a delivery failure that N7 accepts but users will not); too-frequent re-puts
waste bandwidth and, worse, make the record's write pattern a distinctive metadata fingerprint
(feeding A1). The subscriber-sharing idea is attractive for feeds (it makes a popular feed *more*
available the more it is read, the opposite of a server that gets *less* available under load) but
directly collides with recipient privacy (N2), because re-putting is a public act linkable to
readership.

**Current best guess.** Publisher re-puts on a timer keyed to observed DHT TTL (mainline expiry is
on the order of hours), with the interval a tuned constant. Subscriber-assisted republication is
unspecified; the naive version leaks readership. A privacy-preserving version might have subscribers
re-put through the same cover/k-anonymity machinery as A1 (re-put many records, only some of which you
actually read), which ties this question's cost directly to A1's cover-traffic budget.

**What a good answer looks like.** (1) A re-put interval as a function of measured churn and target
availability (a number, backed by DHT measurement, replacing a guessed constant). (2) A subscriber-
sharing scheme with a stated privacy property: either "subscribers re-put under cover so readership is
hidden to within anonymity-set `k`" (and its cost, via A1), or a reasoned "subscriber republication
cannot be made private, so the publisher bears it alone." Updates the availability notes in
06-mailbox.md and 07-feed.md.

**Difficulty:** medium. **Gating:** blocks-v1 for the publisher re-put interval (async channels do
not work without it); subscriber-sharing is later.

### C2. NAT traversal and connectivity for phantom swarms and direct sessions

**Question.** The live channels (phantom swarm C2, cover-seed C3, presence-to-session escalation C7)
require two peers to form a *direct* peer-wire connection after finding each other in the DHT
(05-session.md, 03-conventions.md 3.8). But most consumer peers are behind NAT and cannot accept
inbound connections. BitTorrent handles this partly via the tracker/DHT giving both endpoints and via
hole-punching (uTP, BEP's hole-punch extension), but two symmetric-NAT peers may be unable to connect
at all without a relay. How does Riptide establish a direct session when both parties are behind NAT,
and what does it fall back to when direct connection is impossible?

**Why it matters.** A realtime channel that only works when at least one party has a public IP or a
cooperative NAT works for a minority of consumer deployments. If the fallback is a relay, that relay
sees both IPs (a rung-4 swarm-insider position) and is a partial reintroduction of the server Riptide
exists to avoid. This gates C2/C3/C7 from "works in the lab" to "works for real users on phones behind
carrier-grade NAT."

**Current best guess.** Lean on BitTorrent's existing NAT machinery (uTP, DHT-assisted hole-punching,
and the swarm's natural mix of connectable and non-connectable peers). For the both-symmetric-NAT case,
the honest fallback is a relayed connection, which should reuse the multi-hop relay track (C4 below) so
the relay is untrusted-for-content (end-to-end encryption holds) even though it learns IPs. The
cover-seed mode is somewhat helped here because both peers are already in a real swarm and may already
have a connection for cover reasons.

**What a good answer looks like.** A connectivity design that states the fraction of peer pairs that
can connect directly (measured or modeled against real NAT-type distributions), the hole-punching
mechanism used, and the relayed fallback's exact privacy cost (which rung the relay operates at, what
it learns). Updates 05-session.md's assumptions.

**Difficulty:** medium (mostly engineering over known techniques, but the symmetric-NAT case is
genuinely hard). **Gating:** blocks-v1 for the realtime channels (a realtime channel that cannot
connect real users is not a channel); the async channels (mailbox, feed) do not depend on it.

### C3. Is a swarm-native mixnet viable, or does it reduce to "just use Tor underneath"?

**Question.** The multi-hop relay (C10 in brainstorm.md, 10-anti-abuse-and-privacy.md) onion-wraps a
message through willing swarm peers so the write to a recipient's inbox does not come from the
sender's address, addressing N1 (no IP anonymity by default). The honest doubt, flagged in brainstorm
itself: is a swarm-native mixnet actually viable, or does building it well inevitably reproduce
Tor/I2P, at which point "run Riptide over Tor" is the simpler and more battle-tested answer? The
sub-questions that decide it: **relay incentives** (why would a swarm peer spend bandwidth relaying
others' messages?), **Sybil resistance** (a cheap-to-run relay set is trivially Sybil'd, and a mixnet
whose relays are mostly adversarial provides no anonymity), and **timing correlation** (a low-latency
relay is trivially correlated end-to-end by a rung-5 observer; a high-latency mix defeats correlation
but makes the channel async-only and slow).

**Why it matters.** N1 is one of Riptide's two most-quoted limits, and multi-hop is its only native
answer. If the native mixnet is not viable, the spec should say so plainly and route users to Tor/I2P
(which 01-threat-model.md already mentions as the alternative), rather than shipping a
weak-anonymity relay that gives users false confidence, which is worse than no relay (principle 5,
"say what you cannot protect"). The Sybil question is the crux: an anonymity network with no
Sybil-resistant relay-selection is anonymity theater.

**Current best guess.** brainstorm C10 already tags this "speculative and hard ... a research track,
not a v1 feature," and 01-threat-model.md N1 calls multi-hop "itself an open research track, not a
finished guarantee." The realistic near-term answer is "run over Tor/I2P for IP anonymity; the native
relay is R&D." A native relay might still earn its place for the *specific* narrow job of decoupling
the inbox-write source address for async messages (a single hop, not a full mixnet), where the
latency tolerance is high and the anonymity goal is modest (defeat a rung-3 crawler's source-address
logging, not a rung-5 correlator). Even that needs a relay-incentive and Sybil answer.

**What a good answer looks like.** A decision, backed by analysis: either (a) a specific, bounded
relay design (probably single-hop, async-only, for source-address decoupling) with stated relay
incentives, a Sybil-resistant relay-selection scheme, and an explicit statement of which adversary
rung it defeats (and which, notably rung-5 correlation, it does not); or (b) a reasoned rejection,
"a swarm-native mixnet reduces to a worse Tor; use Tor underneath," which simplifies the spec and is
itself a valuable result. Either way, 10-anti-abuse-and-privacy.md stops presenting multi-hop as an
open-ended promise.

**Difficulty:** high. **Gating:** later. v1 ships with N1 stated and Tor/I2P as the recommended IP
anonymity path; the native relay is explicitly R&D.

### C4. Relay-operator abuse and legal exposure

**Question.** Any relay Riptide introduces (the multi-hop relays of C3, or the NAT-traversal relay
fallback of C2) forwards other users' encrypted traffic. The operator cannot see the content
(end-to-end encryption holds), which is the technical safeguard, but is nonetheless carrying and
re-emitting third-party traffic they cannot inspect, from their own IP. What is the abuse and legal
exposure of running a relay, and does that exposure make relays so unattractive that the relay set is
too small (and thus too Sybil-able, feeding C3's Sybil problem) to provide anonymity?

**Why it matters.** This is the Tor-exit-node problem transplanted. If honest volunteers will not run
relays because of the legal risk of emitting traffic they cannot see, the only relays left are those
run by adversaries or by people who do not understand the risk, which is a security failure (C3's
Sybil crux) dressed as a governance problem. brainstorm section 9 flags that "piggybacking on public
swarms has legal and ToS dimensions"; the relay case is sharper because the operator is emitting
others' content, not just their own cover traffic.

**Current best guess.** Unaddressed beyond brainstorm section 9's general note. The likely
mitigations are the standard Tor-relay ones (operator-set policies on what to relay, rate limits,
clear documentation of legal posture by jurisdiction) plus keeping relays optional and off by default.
The content-blindness (relays cannot see plaintext) is the main defense but does not eliminate the
exposure of emitting the traffic.

**What a good answer looks like.** An operator-risk assessment per major jurisdiction and a relay
design that minimizes exposure (content-blind by construction, minimal logging, clear operator
controls), plus an honest statement to prospective operators. This is as much a legal and governance
question as a technical one, and it feeds directly into whether C3's relay set can ever be large
enough.

**Difficulty:** medium (spans legal and technical). **Gating:** later (only relevant once relays
exist, which is post-v1 per C2 fallback and C3).

---

## D. Governance and assurance

### D1. The case for a formal security analysis or proof

**Question.** Riptide "adds no cryptography of its own; it composes audited primitives"
(01-threat-model.md trust assumptions, 00-overview.md principle 1). But *composition* is where
protocols fail even when every primitive is sound: the handshake (05-session.md), the ratchet
(06-mailbox.md, context `rp-ratch`), the associated-data binding that stops replay and reorder
(03-conventions.md 3.5.1), and the epoch/derived-id scheme (04-rendezvous.md) are novel compositions
that no audit of libsodium covers. Which Riptide properties most need a formal analysis or proof, and
what is the right tool (a symbolic model in Tamarin/ProVerif for the handshake and key-agreement, a
computational proof for the ratchet, a hand analysis for the metadata properties)?

**Why it matters.** The README and 01-threat-model.md are careful to say Riptide is "not yet
independently reviewed, and not yet a security guarantee." Turning that into a guarantee for the core
properties (G1-G4) requires analysis of the *composition*, not just trust in the primitives. The
highest-value targets are the pieces where a subtle composition bug silently breaks a stated guarantee:
the session handshake (does it actually authenticate both parties and agree a fresh key against a
rung-3 MITM?), the replay/reorder binding (does the `ad = {e, q, t}` construction actually prevent
every replay and cross-channel reuse?), and the prekey/X3DH-style agreement (does the fallback to
SPK-only when OPKs are exhausted preserve the forward-secrecy claim?).

**Current best guess.** No formal analysis exists; the assurance today is careful design plus the
conformance vectors (12-conformance-vectors.md) that pin derivations and encodings (which catch
implementation drift, not design flaws). The static checker (tools/check-livecodescript.py) and the
smoke tests catch code-level bugs, not protocol-level ones.

**What a good answer looks like.** A prioritized assurance plan: a symbolic model of the session
handshake and the mailbox handshake in a tool like Tamarin or ProVerif proving mutual authentication,
key secrecy, and forward secrecy against the rung-3 active adversary; a focused argument (formal or
rigorous-by-hand) that the AD-binding of 3.5.1 prevents replay, reorder, and cross-channel/cross-epoch
reuse; and a clear statement of which properties are proven, which are argued, and which remain
assumptions. This directly upgrades the README's "not yet a security guarantee."

**Difficulty:** high (a formal-methods project), but decomposable (the handshake model alone is a
bounded, high-value first target). **Gating:** later for the full analysis; the handshake model is a
strong candidate for a v1-blocking subset, because the handshake is the one place a composition bug
would silently void G1-G3 against the very adversary (rung-3 MITM) that 02-identity.md's verification
machinery exists to stop.

### D2. Additional forks noted for completeness

Smaller open items surfaced while reading the foundation, each stated briefly so they are not lost:

- **Seeded box/kx keypairs (blocks the one-seed claim).** 02-identity.md 2.2 and 2.6 note that ids 1
  and 2 (the X25519 and kx keys) cannot yet be derived deterministically from `S` because SodiumXT
  does not expose `crypto_box_seed_keypair` / `crypto_kx_seed_keypair` or the ed25519-to-X25519
  conversion (11-capabilities-required.md). Until it does, "one seed, two networks, one backup" is
  literally false (the encryption keys are separate stored blobs). This is not research, it is a
  scoped SodiumXT capability, but it *blocks* the headline identity claim and should be tracked as
  such. **Difficulty:** low. **Gating:** blocks-v1 for the one-backup claim; the protocol works
  without it (store the extra keys), the marketing does not.

- **k-of-n secret sharing for dead-man / time-lock messages (C9).** C9 in brainstorm.md needs a
  Shamir-style secret-sharing layer over a key, which neither SodiumXT nor Riptide currently provides
  (11-capabilities-required.md would need it). Whether to add it, and whether the "publish on my
  silence" trigger can be made robust against both premature and suppressed triggering, is an open
  design question. **Difficulty:** medium. **Gating:** later (C9 is not a core channel).

- **Recognition-token unlinkability across cover-seed sessions.** 03-conventions.md 3.8 and C3 require
  the "this peer speaks Riptide" token to be unlinkable across sessions (rotate per epoch), but the
  exact derivation and its unlinkability against a peer that logs tokens over time is not pinned down;
  it couples to A1 (linkage) and A2 (cover-seed). **Difficulty:** low to medium. **Gating:** blocks-v1
  for cover-seed (a linkable recognition token defeats the mode's purpose).

- **Feed reader revocation at scale (C4).** 07-feed.md rotates the feed read key via `rp-feedk` to
  revoke readers, but revoking one reader from a large audience by rekey is the same O(N)
  redistribution problem as B1's group case, and the subscriber *set* is observable at the swarm level
  (brainstorm C4 limit). Whether large-audience revocation is tractable without a tree is the feed-side
  of B1. **Difficulty:** high. **Gating:** later.

---

## Reading: what most gates a real deployment

Two questions gate a real deployment more than the rest.

**B3 (anti-spam for open inboxes) is the sharpest v1 blocker.** The mailbox is the core async channel
and its whole premise is that a stranger can send you a first message at an id derived from your public
key. That is a world-writable inbox with no server to rate-limit it, so on first real exposure it
becomes a spam and malware sink, and the design commitments (principle 7, "consent not reach"; the
prekey-bundle first-contact flow) both depend on getting the gate right. It is only medium difficulty,
but nothing about the mailbox is safely shippable until it is answered, and the wrong answer (pure
capability tokens) silently closes the inbox the design promises to keep open.

**A1 plus A2 (quantified metadata privacy, and whether cover-seed deniability survives) gate the
project's identity, not just a channel.** Riptide's distinctive promise over "just use Signal" is
metadata resistance and deniable transport riding real BitTorrent. Both are currently stated only as
"raises the cost" (N2) and an unmeasured tier-3 claim (G6). Until A1 produces a real operating point
(epoch length, anonymity-set size, cover rate, and the residual linkage probability) and A2 establishes
whether a tracker-running traffic analyst can unmask a cover-seed connection, the headline privacy
claims are aspirational. v1 can ship honestly with the limits stated exactly as 01-threat-model.md
already does, but the project cannot *market* metadata privacy or cover-seed deniability as features
until these two are answered. If forced to pick one, A2 is the more existential: cover-seed is the
single most novel idea in the whole design (brainstorm calls it "the most interesting corner"), and if
its deniability does not survive a realistic tracker-plus-tap adversary, the strongest thing Riptide
claims to be is not true, and the spec should say so before users rely on it.

Everything else is either a stated-limit-plus-fast-follow (B1 groups, B2 key-transparency gossip, C1
subscriber republication) or genuine post-v1 R&D (C3 mixnet, C4 relay exposure, D1 full formal proof),
and the honest-limits posture of 01-threat-model.md lets v1 ship around them without overclaiming.
