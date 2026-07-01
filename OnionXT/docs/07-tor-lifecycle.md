# 07 - Tor Lifecycle: Assume-Running vs Launch-a-Binary

OnionXT talks to a tor daemon; it does not embed one. But "where does the daemon come from" is a real
product question with two answers, and OnionXT should support both without letting the convenient one
become a hidden dependency.

## Mode A: assume a running daemon (the default, the tested path)

The app assumes tor is already reachable on the loopback SOCKS and control ports. This is true when:

- The user runs **Tor Browser** (SOCKS `9150`, control `9151`; control port and cookie auth may need
  enabling in its config).
- The user runs a **system tor** (Linux/macOS package, `SocksPort 9050`, `ControlPort 9051`).
- An ops team runs a managed tor alongside the app.

This is the default because it is the simplest, the most testable, and it keeps OnionXT free of any
native binary or process management. All of the plan's phases target this mode. Bring-up `torrc`:

```
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
```

The app should detect the daemon (`oxConnectControl` + a `GETINFO version`) and, if it is absent,
present a clear "start Tor / install Tor" message rather than failing obscurely.

## Mode B: launch and supervise a bundled binary (optional convenience, Phase 8)

For a turnkey app, OnionXT can start its own tor as a child process, using the engine's `open process`
/ shell facilities:

1. Write a minimal `torrc` to a temp/app-support directory (its own `DataDirectory`, a `SocksPort`, a
   `ControlPort`, `CookieAuthentication 1`, and ideally `ControlPort auto` + `__OwningControllerProcess`
   so tor exits if the app dies).
2. Launch the bundled `tor` binary with `-f <that torrc>` via `open process ... for read` (or a
   platform shell), capturing stdout to watch for the `Bootstrapped 100%` line.
3. Connect the control port, subscribe to `STATUS_CLIENT`, and surface bootstrap progress.
4. On app exit (for example `closeStack`), send `SIGNAL SHUTDOWN` over the control port (or terminate
   the process), and clean up the temp `torrc`/`DataDirectory`.

Considerations, called out honestly:

- **Bundling tor is a licensing and size decision.** The Tor binary is BSD-3-licensed but large, and
  shipping it (per platform) is a real distribution cost. Prefer a documented "install Tor" path for
  most apps; bundle only when the product truly needs zero-config.
- **Trademark / distribution.** Redistributing a tor binary has naming and packaging expectations from
  the Tor Project; follow them, and never imply endorsement.
- **The default stays Mode A.** Mode B is a convenience layer behind an explicit flag. The tested,
  documented, and recommended path is a daemon the user or ops controls, because that daemon is part of
  the trusted base (doc 01): a bundled binary the app auto-launches must still be a genuine, unmodified
  tor, and the user should be able to verify or replace it.

## Bootstrap UX (both modes)

- A cold tor takes tens of seconds to bootstrap; an onion service takes seconds more to publish its
  descriptor before it is reachable. Never freeze the UI: read `STATUS_CLIENT BOOTSTRAP PROGRESS=NN`
  (or poll `GETINFO status/bootstrap-phase`) and `HS_DESC`, and show explicit progress at <= ~4 Hz.
- Distinguish the states a user cares about: "connecting to Tor," "bootstrapping NN%," "publishing your
  address," "reachable." A stalled bootstrap (blocked network, censored Tor) should time out into a
  clear, actionable message, not an indefinite spinner.
