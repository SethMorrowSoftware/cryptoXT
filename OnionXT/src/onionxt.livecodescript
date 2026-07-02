-- onionxt.livecodescript - the OnionXT library skeleton.
--
-- OnionXT is a Tor transport and rendezvous layer for OpenXTalk / the xTalk
-- family. It speaks SOCKS5 (RFC 1928 + Tor extensions) and the Tor control
-- protocol to a LOCALLY-RUNNING tor daemon; it does not embed or ship Tor.
-- It adds no cryptography (SodiumXT does that) and, in this v1 form, no native
-- code (the SOCKS5 and control clients are engine socket I/O).
--
-- THIS IS A SKELETON. Every public handler below is stubbed and reports that
-- it is not implemented. The bodies are built in the order of
-- IMPLEMENTATION-PLAN.md, against the byte- and line-level specs in
-- docs/02-socks5-client.md and docs/03-control-port.md. Nothing here has run on
-- an OXT engine yet: it is designed and statically reasoned, and needs an
-- on-engine pass against a real tor daemon.
--
-- Conventions (see CLAUDE.md): public API oxPascalCase; locals t..., params
-- p..., script-locals s..., constants k...; SOCKS5 is BINARY (byte / numToByte
-- / byteToNum), the control protocol is CRLF text; every socket op is async
-- (open / read / accept with message) so the one interpreter thread never
-- blocks on the network; loopback (127.0.0.1) only; every open has an
-- idempotent close.

-- Loopback host is fixed; only the ports are configurable (and loopback-locked).
constant kOxHost = "127.0.0.1"
constant kOxSocksPortDefault = 9050
constant kOxControlPortDefault = 9051
constant kOxVersion = "0.1.0-framework"

-- Configurable ports (default to a system tor; Tor Browser uses 9150 / 9151).
local sSocksPort
local sControlPort
-- Control-connection and bootstrap state (see docs/03-control-port.md).
local sControlSocket        -- the engine id of the open control socket, or empty
local sBootstrap            -- 0..100 bootstrap percent from STATUS_CLIENT
-- App-registered callback handler names.
local sStatusCallback       -- coalesced bootstrap / event updates
local sPeerCallback         -- a peer connected to one of our published services
-- Handle tables (script-side; a stale id must be a clean error, never a crash).
local sStreams              -- dialed SOCKS streams, keyed by handle
local sServices             -- published onion services, keyed by handle

-- ==========================================================================
-- Configuration.
-- ==========================================================================

command oxSetSocksPort pPort
   put pPort into sSocksPort
end oxSetSocksPort

command oxSetControlPort pPort
   put pPort into sControlPort
end oxSetControlPort

function oxVersion
   -- Once the control connection is up, append the tor version from
   -- GETINFO version (TODO phase 2). For now, just the library version.
   return kOxVersion
end oxVersion

-- ==========================================================================
-- Control connection and bootstrap (docs/03-control-port.md, plan phase 2).
-- ==========================================================================

command oxConnectControl
   -- TODO(phase 2): open socket to kOxHost & ":" & effectiveControlPort() with
   -- message, PROTOCOLINFO 1, then authenticate (SAFECOOKIE > COOKIE > NULL >
   -- HASHEDPASSWORD). Report success/failure in the result.
   return notImplemented("oxConnectControl")
end oxConnectControl

command oxDisconnectControl
   -- TODO(phase 2): idempotent close of the control socket.
   put empty into sControlSocket
end oxDisconnectControl

function oxBootstrapProgress
   -- TODO(phase 6): driven by STATUS_CLIENT BOOTSTRAP PROGRESS= events.
   if sBootstrap is empty then
      return 0
   end if
   return sBootstrap
end oxBootstrapProgress

function oxIsReady
   -- TODO(phase 6): true once bootstrapped to 100 and any service descriptor
   -- has uploaded (HS_DESC). Stubbed false.
   return false
end oxIsReady

command oxSetStatusCallback pHandlerName
   put pHandlerName into sStatusCallback
end oxSetStatusCallback

-- ==========================================================================
-- Outbound: dialing through SOCKS5 (docs/02-socks5-client.md, plan phase 1).
-- ==========================================================================

command oxDial pHost, pPort
   -- TODO(phase 1): SOCKS5 CONNECT with ATYP=3 (domain name) so Tor resolves
   -- pHost (a .onion or clearnet name) - never resolve it locally (DNS leak).
   -- Report a stream handle in the result, or a mapped SOCKS REP error.
   return notImplemented("oxDial")
end oxDial

command oxWrite pStream, pData
   -- TODO(phase 1): write pData (already sealed by the app / Riptide via
   -- SodiumXT) to the tunneled socket for pStream. OnionXT does not encrypt.
   return notImplemented("oxWrite")
end oxWrite

command oxSetStreamCallback pStream, pHandlerName
   -- TODO(phase 1): register the handler the async read loop calls with each
   -- inbound Data chunk on pStream. The app reassembles its own framing.
   return notImplemented("oxSetStreamCallback")
end oxSetStreamCallback

command oxCloseStream pStream
   -- TODO(phase 1): idempotent close of the stream socket and forget pStream.
   return notImplemented("oxCloseStream")
end oxCloseStream

-- ==========================================================================
-- Inbound: onion services (docs/03, docs/04, plan phases 3 and 5).
-- ==========================================================================

command oxCreateService pVirtualPort, pLocalPort
   -- TODO(phase 3): start accepting on 127.0.0.1:pLocalPort FIRST, then
   -- ADD_ONION NEW:ED25519-V3 Port=pVirtualPort,127.0.0.1:pLocalPort. Report
   -- the full <56>.onion address and a service handle.
   return notImplemented("oxCreateService")
end oxCreateService

command oxCreateServiceFromSeed pSeed, pVirtualPort, pLocalPort
   -- TODO(phase 5): derive the ed25519 identity from pSeed via SodiumXT and get
   -- Tor's 64-byte ED25519-V3 expanded key with sxSignSeedToExpandedKey (shipped
   -- in SodiumXT ABI 6), then pass it to ADD_ONION ED25519-V3:<key> so the .onion
   -- address is reproducible from the seed.
   return notImplemented("oxCreateServiceFromSeed")
end oxCreateServiceFromSeed

command oxRemoveService pService
   -- TODO(phase 3): DEL_ONION and stop the listener. Idempotent.
   return notImplemented("oxRemoveService")
end oxRemoveService

function oxServiceAddress pService
   -- TODO(phase 3): the .onion address for a published service handle.
   return empty
end oxServiceAddress

command oxSetPeerCallback pHandlerName
   put pHandlerName into sPeerCallback
end oxSetPeerCallback

-- ==========================================================================
-- Address helpers: a v3 .onion address IS an ed25519 public key
-- (docs/04-onion-rendezvous.md). Pure, no network.
-- ==========================================================================

function oxAddressFromPublicKey pEd25519Pub
   -- TODO(phase 5): base32( pubkey || checksum || 0x03 ) & ".onion". The
   -- checksum needs SHA3-256 (SodiumXT gap, docs/08); base32 is pure bytes.
   return notImplemented("oxAddressFromPublicKey")
end oxAddressFromPublicKey

function oxPublicKeyFromAddress pOnionAddress
   -- TODO(phase 5): strip ".onion", base32-decode the 56 chars to 35 bytes,
   -- return the first 32 (the ed25519 public key). No crypto needed.
   return notImplemented("oxPublicKeyFromAddress")
end oxPublicKeyFromAddress

function oxIsValidAddress pOnionAddress
   -- TODO(phase 5): structural check now; checksum check once SHA3-256 lands.
   return false
end oxIsValidAddress

-- ==========================================================================
-- Internal helpers.
-- ==========================================================================

private function effectiveSocksPort
   if sSocksPort is empty then
      return kOxSocksPortDefault
   end if
   return sSocksPort
end effectiveSocksPort

private function effectiveControlPort
   if sControlPort is empty then
      return kOxControlPortDefault
   end if
   return sControlPort
end effectiveControlPort

-- Uniform "framework stub" reply, so a caller sees a clear, honest error
-- rather than silence while the bodies are being built out phase by phase.
private function notImplemented pWhat
   return "OnionXT: " & pWhat & " is not implemented yet (see IMPLEMENTATION-PLAN.md)"
end notImplemented
