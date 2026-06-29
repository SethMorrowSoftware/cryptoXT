-- sodium-demo.livecodescript - an interactive SodiumXT showcase stack.
--
-- This is the script of a demo stack. On open it builds its own UI and then
-- shows off the WHOLE library, two ways:
--
--   1. A hands-on panel: type a passphrase and a message, then Encrypt /
--      Decrypt / Hash. This is the headline upgrade over the old aes-256-cbc +
--      weak-KDF path: a random salt is drawn, the key is derived with Argon2id,
--      the message is sealed with secretbox, and the salt travels with the
--      ciphertext so decryption can re-derive the key.
--
--   2. A guided "capability tour": one button per category (hashing, passwords,
--      secret-key, public-key, signatures, key exchange, streaming, files) plus
--      a "Run Full Tour" that runs them all. Each writes a narrated, step-by-step
--      transcript into the log field, so a presenter can show the full surface
--      live: BLAKE2b + hex/base64, Argon2id + KDF, secretbox + AEAD, X25519 box +
--      sealed box, ed25519 sign/verify, crypto_kx, secretstream, and whole-file
--      encryption.
--
-- To use (requires the SodiumXT extension installed so org.openxtalk.library
-- .sodium is loaded): open this as a script-only stack, OR create a stack, paste
-- this as its stack script, and `send "preOpenStack" to <that stack>`.
--
-- NOTE on the Data-based API: bytes cross as Data; this script textEncodes the
-- passphrase/message to UTF-8 on the way in and textDecodes hex/base64/plaintext
-- on the way out. The out-parameter call forms (sxBoxKeypair tPk, tSk ; the
-- secretstream and kx handlers) match examples/sodium-tests.livecodescript so a
-- single OXT pass reconciles both.
--
-- Verified statically (tools/check-livecodescript.py); run it in OXT to confirm.

-- The last base64(salt + box) produced by the hands-on Encrypt button, so the
-- Decrypt button can recover it without coupling to the log field.
local sLastBlob

on preOpenStack
   buildDemoUI
end preOpenStack

-- ==========================================================================
-- UI construction (idempotent).
-- ==========================================================================

on buildDemoUI
   if there is a field "fIn" then
      exit buildDemoUI
   end if
   set the width of this stack to 760
   set the height of this stack to 720
   set the name of this stack to "SodiumXT Demo"

   makeLabel "lTitle", "SodiumXT - modern cryptography for xTalk", "20,12,740,38"
   set the textSize of field "lTitle" to 18
   set the textStyle of field "lTitle" to "bold"

   makeLabel "lVer", "", "20,40,740,60"
   try
      put sxVersion() into field "lVer"
   catch tErr
      put "SodiumXT library is not loaded:" && tErr into field "lVer"
   end try

   makeLabel "lPass", "Passphrase", "20,70,740,90"
   makeField "fPass", "20,92,740,120"
   makeLabel "lIn", "Message", "20,128,740,148"
   makeField "fIn", "20,150,740,210"

   -- Hands-on row.
   makeButton "Encrypt", "20,218,180,250"
   makeButton "Decrypt", "200,218,360,250"
   makeButton "Hash", "380,218,540,250"

   makeLabel "lTour", "Capability tour (each button narrates into the log below):", "20,258,740,278"

   -- Category rows.
   makeButton "Hashing", "20,282,190,314"
   makeButton "Passwords", "200,282,370,314"
   makeButton "Secret-key", "380,282,550,314"
   makeButton "Public-key", "560,282,730,314"

   makeButton "Signatures", "20,320,190,352"
   makeButton "Key Exchange", "200,320,370,352"
   makeButton "Streaming", "380,320,550,352"
   makeButton "Files", "560,320,730,352"

   makeButton "Run Full Tour", "20,358,360,390"
   makeButton "Clear", "380,358,540,390"

   makeLabel "lOut", "Log", "20,398,740,418"
   makeField "fOut", "20,420,740,700"
   set the lockText of field "fOut" to true
   set the vScrollbar of field "fOut" to true
   set the textFont of field "fOut" to "Courier"
   set the textSize of field "fOut" to 11

   put "secret passphrase" into field "fPass"
   put "Attack at dawn." into field "fIn"
   put "Click Run Full Tour, or any single category button. Or type a" & return & \
      "passphrase and message above and use Encrypt / Decrypt / Hash." into field "fOut"
end buildDemoUI

private command makeField pName, pRect
   create field pName
   set the rectangle of field pName to pRect
   set the lockText of field pName to false
end makeField

private command makeLabel pName, pCaption, pRect
   create field pName
   set the rectangle of field pName to pRect
   set the lockText of field pName to true
   set the showBorder of field pName to false
   set the backgroundColor of field pName to empty
   put pCaption into field pName
end makeLabel

private command makeButton pName, pRect
   create button pName
   set the rectangle of button pName to pRect
end makeButton

-- ==========================================================================
-- Click routing (the buttons carry no script of their own).
-- ==========================================================================

on mouseUp
   local tName
   put the short name of the target into tName
   if tName is "Encrypt" then
      doEncrypt
   else if tName is "Decrypt" then
      doDecrypt
   else if tName is "Hash" then
      doHash
   else if tName is "Hashing" then
      doHashing
   else if tName is "Passwords" then
      doPasswords
   else if tName is "Secret-key" then
      doSecretKey
   else if tName is "Public-key" then
      doPublicKey
   else if tName is "Signatures" then
      doSignatures
   else if tName is "Key Exchange" then
      doKeyExchange
   else if tName is "Streaming" then
      doStreaming
   else if tName is "Files" then
      doFiles
   else if tName is "Run Full Tour" then
      doFullTour
   else if tName is "Clear" then
      put empty into field "fOut"
   end if
end mouseUp

-- ==========================================================================
-- Output + small conveniences.
-- ==========================================================================

on sayLn pLine
   put pLine & return after field "fOut"
   set the vScroll of field "fOut" to the formattedHeight of field "fOut"
end sayLn

on sayHead pTitle
   if field "fOut" is not empty then
      put return after field "fOut"
   end if
   put "=== " & pTitle && "===" & return after field "fOut"
   set the vScroll of field "fOut" to the formattedHeight of field "fOut"
end sayHead

-- hex string of some bytes (sxBin2Hex returns the ASCII hex as Data)
private function uHex pData
   return textDecode(sxBin2Hex(pData), "ascii")
end uHex

-- UTF-8 bytes of a string (pin the encoding so it is the same on every machine)
private function u8 pText
   return textEncode(pText, "utf-8")
end u8

-- ==========================================================================
-- Hands-on panel: passphrase -> Argon2id -> secretbox.
-- ==========================================================================

on doEncrypt
   local tSalt
   local tKey
   local tBox
   local tBlob
   if field "fPass" is empty then
      sayHead "Encrypt"
      sayLn "Enter a passphrase first."
      exit doEncrypt
   end if
   sayHead "Encrypt (passphrase -> Argon2id key -> secretbox)"
   put sxRandomBytes(16) into tSalt
   put sxPwHash(u8(field "fPass"), tSalt, 32, "2", sxPwMemInteractive()) into tKey
   put sxSecretBox(u8(field "fIn"), tKey) into tBox
   put textDecode(sxBin2Base64(tSalt & tBox), "ascii") into tBlob
   put tBlob into sLastBlob
   sayLn "Output is base64(salt + nonce + ciphertext + MAC):"
   sayLn "  " & tBlob
end doEncrypt

on doDecrypt
   local tRaw
   local tSalt
   local tBox
   local tKey
   sayHead "Decrypt"
   if sLastBlob is empty then
      sayLn "Nothing to decrypt yet; click Encrypt first."
      exit doDecrypt
   end if
   put sxBase642Bin(textEncode(sLastBlob, "ascii")) into tRaw
   put byte 1 to 16 of tRaw into tSalt
   put byte 17 to -1 of tRaw into tBox
   put sxPwHash(u8(field "fPass"), tSalt, 32, "2", sxPwMemInteractive()) into tKey
   try
      sayLn "Recovered plaintext:" && textDecode(sxSecretBoxOpen(tBox, tKey), "utf-8")
   catch tErr
      sayLn "Wrong passphrase, or the ciphertext was tampered with."
   end try
end doDecrypt

on doHash
   sayHead "Hash (BLAKE2b-256 of the message)"
   sayLn uHex(sxHash(u8(field "fIn"), 32))
end doHash

-- ==========================================================================
-- Capability tour.
-- ==========================================================================

on doHashing
   local tMsg
   local tDigest
   local tB64
   local tRound
   local tKey
   local tMac
   sayHead "Hashing and encoding (BLAKE2b, hex, base64)"
   put u8("The quick brown fox jumps over the lazy dog") into tMsg
   put sxHash(tMsg, 32) into tDigest
   sayLn "BLAKE2b-256:" && uHex(tDigest)
   put sxBin2Base64(tDigest) into tB64
   sayLn "  base64 (url-safe, no padding):" && textDecode(tB64, "ascii")
   put sxBase642Bin(tB64) into tRound
   sayLn "  base64 decodes back to the same bytes:" && sxMemEqual(tRound, tDigest)
   put sxRandomBytes(32) into tKey
   put sxHashKeyed(tMsg, tKey, 32) into tMac
   sayLn "Keyed BLAKE2b (a MAC):" && uHex(tMac)
   sayLn "  the keyed hash differs from the unkeyed one:" && (not sxMemEqual(tMac, tDigest))
end doHashing

on doPasswords
   local tPass
   local tSalt
   local tKey
   local tHash
   local tHashS
   local tMaster
   local tCtx
   local tK1
   local tK2
   sayHead "Passwords and key derivation (Argon2id, KDF)"
   put u8("correct horse battery staple") into tPass
   put sxRandomBytes(16) into tSalt
   put sxPwHash(tPass, tSalt, 32, "2", sxPwMemInteractive()) into tKey
   sayLn "Argon2id derived a 32-byte key (opslimit 2, memlimit" && sxPwMemInteractive() & " bytes):"
   sayLn "  " & uHex(tKey)
   put sxPwHashStr(tPass, "2", sxPwMemInteractive()) into tHash
   put textDecode(tHash, "ascii") into tHashS
   sayLn "Self-describing hash string for storage (packs salt + cost):"
   sayLn "  " & tHashS
   sayLn "  verify the right passphrase (true):" && sxPwHashStrVerify(tHashS, tPass)
   sayLn "  verify a wrong passphrase (false):" && sxPwHashStrVerify(tHashS, u8("not it"))
   put sxRandomBytes(32) into tMaster
   put u8("Examples") into tCtx
   put sxKdfDerive(tMaster, "1", tCtx, 32) into tK1
   put sxKdfDerive(tMaster, "2", tCtx, 32) into tK2
   sayLn "KDF subkey #1 from one master key:" && uHex(tK1)
   sayLn "  subkey #2 is independent of #1:" && (not sxMemEqual(tK1, tK2))
end doPasswords

on doSecretKey
   local tKey
   local tMsg
   local tBox
   local tAd
   local tCt
   local tOk
   sayHead "Secret-key authenticated encryption (secretbox, AEAD)"
   put sxRandomBytes(32) into tKey
   put u8("Meet at the docks at midnight.") into tMsg
   put sxSecretBox(tMsg, tKey) into tBox
   sayLn "secretbox sealed a" && (the number of bytes in tMsg) & "-byte message into" && \
      (the number of bytes in tBox) & " bytes (nonce + ciphertext + MAC)."
   sayLn "  opened:" && textDecode(sxSecretBoxOpen(tBox, tKey), "utf-8")
   put u8("context: invoice #42") into tAd
   put sxAeadEncrypt(tMsg, tAd, tKey) into tCt
   sayLn "AEAD additionally binds associated data:" && textDecode(tAd, "ascii")
   put true into tOk
   try
      get sxAeadDecrypt(tCt, u8("context: invoice #43"), tKey)
      put false into tOk
   catch tErr
      put true into tOk
   end try
   sayLn "  changing the associated data is detected and rejected:" && tOk
end doSecretKey

on doPublicKey
   local tApk
   local tAsk
   local tBpk
   local tBsk
   local tMsg
   local tBox
   local tSealed
   sayHead "Public-key encryption (X25519 box, sealed box)"
   sxBoxKeypair tApk, tAsk
   sxBoxKeypair tBpk, tBsk
   sayLn "Generated X25519 keypairs for Alice and Bob."
   put u8("Hi Bob, this is Alice.") into tMsg
   put sxBox(tMsg, tBpk, tAsk) into tBox
   sayLn "box (Alice -> Bob), opened by Bob:" && textDecode(sxBoxOpen(tBox, tApk, tBsk), "utf-8")
   put sxSeal(u8("From an anonymous sender."), tBpk) into tSealed
   sayLn "sealed box (sender stays anonymous), opened by Bob:" && \
      textDecode(sxSealOpen(tSealed, tBpk, tBsk), "utf-8")
end doPublicKey

on doSignatures
   local tPk
   local tSk
   local tMsg
   local tSig
   local tSigned
   local tSeed
   local tPk2
   local tSk2
   sayHead "Digital signatures (ed25519)"
   sxSignKeypair tPk, tSk
   put u8("I authorize transfer of 10 coins.") into tMsg
   put sxSignDetached(tMsg, tSk) into tSig
   sayLn "detached signature (" & (the number of bytes in tSig) & " bytes) verifies:" && \
      sxSignVerifyDetached(tSig, tMsg, tPk)
   sayLn "  a one-word change to the message fails:" && \
      (not sxSignVerifyDetached(tSig, u8("I authorize transfer of 11 coins."), tPk))
   put sxSign(tMsg, tSk) into tSigned
   sayLn "attached signature (signature + message) opens to:" && \
      textDecode(sxSignOpen(tSigned, tPk), "utf-8")
   put sxRandomBytes(32) into tSeed
   sxSignKeypairFromSeed tSeed, tPk2, tSk2
   sayLn "A 32-byte seed gives a deterministic keypair (BEP44-compatible)."
end doSignatures

on doKeyExchange
   local tCpk
   local tCsk
   local tSpk
   local tSsk
   local tCrx
   local tCtx
   local tSrx
   local tStx
   sayHead "Key exchange (crypto_kx)"
   sxKeyExchangeKeypair tCpk, tCsk
   sxKeyExchangeKeypair tSpk, tSsk
   sxKeyExchangeClient tCpk, tCsk, tSpk, tCrx, tCtx
   sxKeyExchangeServer tSpk, tSsk, tCpk, tSrx, tStx
   sayLn "Client and server each derived a shared session-key pair."
   sayLn "  client rx equals server tx:" && sxMemEqual(tCrx, tStx)
   sayLn "  client tx equals server rx:" && sxMemEqual(tCtx, tSrx)
end doKeyExchange

on doStreaming
   local tKey
   local tHeader
   local tPushH
   local tPullH
   local tNoAd
   local tC1
   local tC2
   local tC3
   local tTag
   local tP1
   local tP2
   local tP3
   sayHead "Streaming AEAD (secretstream)"
   put sxRandomBytes(32) into tKey
   put u8("") into tNoAd
   put sxSecretStreamInitPush(tKey, tHeader) into tPushH
   put sxSecretStreamPush(tPushH, u8("Streaming "), tNoAd, false) into tC1
   put sxSecretStreamPush(tPushH, u8("chunk by "), tNoAd, false) into tC2
   put sxSecretStreamPush(tPushH, u8("chunk."), tNoAd, true) into tC3
   sxFreeStream tPushH
   sayLn "Encrypted 3 chunks; the last carries a FINAL tag (truncation is detectable)."
   put sxSecretStreamInitPull(tKey, tHeader) into tPullH
   put sxSecretStreamPull(tPullH, tC1, tNoAd, tTag) into tP1
   put sxSecretStreamPull(tPullH, tC2, tNoAd, tTag) into tP2
   put sxSecretStreamPull(tPullH, tC3, tNoAd, tTag) into tP3
   sayLn "  the final chunk's tag is FINAL:" && sxIsFinalTag(tTag)
   sxFreeStream tPullH
   sayLn "  reassembled stream:" && textDecode(tP1 & tP2 & tP3, "utf-8")
end doStreaming

on doFiles
   local tKey
   local tSrc
   local tEnc
   local tDec
   local tData
   local tOk
   sayHead "Whole-file encryption (streamed C-side; never fully in memory)"
   put sxRandomBytes(32) into tKey
   put specialFolderPath("temporary") & "/sxt_demo_plain.bin" into tSrc
   put specialFolderPath("temporary") & "/sxt_demo.enc" into tEnc
   put specialFolderPath("temporary") & "/sxt_demo_dec.bin" into tDec
   put sxRandomBytes(100000) into tData
   put tData into url ("binfile:" & tSrc)
   try
      sxEncryptFile tSrc, tEnc, tKey
      sxDecryptFile tEnc, tDec, tKey
      put (url ("binfile:" & tDec) is tData) into tOk
      sayLn "Encrypted then decrypted a 100 KB file; the round trip is byte-identical:" && tOk
   catch tErr
      sayLn "File demo skipped (could not use the temporary folder):" && tErr
   end try
   if there is a file tSrc then
      delete file tSrc
   end if
   if there is a file tEnc then
      delete file tEnc
   end if
   if there is a file tDec then
      delete file tDec
   end if
end doFiles

on doFullTour
   put empty into field "fOut"
   sayLn "SodiumXT full capability tour"
   sayLn sxVersion()
   doHashing
   doPasswords
   doSecretKey
   doPublicKey
   doSignatures
   doKeyExchange
   doStreaming
   doFiles
   sayHead "Tour complete"
   sayLn "Every step above ran against the real libsodium through the C shim."
end doFullTour
