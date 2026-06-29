-- sodium-tests.livecodescript - an xTalk self-test harness for SodiumXT.
--
-- Exercises every public sx* capability with round-trips, known-answer vectors,
-- and tamper / wrong-key checks (the negative paths use try/catch, because the
-- sx* handlers throw on an authentication failure rather than return garbage).
--
-- How to run, once the SodiumXT extension is installed (so org.openxtalk.library
-- .sodium is loaded): put this script where its handlers are in scope (e.g. set
-- it as a stack script, or `start using` this script-only stack), then from the
-- message box:
--     put sxSelfTest()
-- It returns a per-check report and a PASSED/FAILED summary.
--
-- NOTE on the Data-based API: hex/base64 and the pwhash string cross as Data
-- (the ASCII bytes); textDecode them here when a String is wanted. A passphrase
-- is textEncoded to UTF-8 before it crosses.
--
-- Verified statically (tools/check-livecodescript.py); run it in OXT to confirm.

local sLog
local sPass
local sFail

function sxSelfTest
   put "SodiumXT self-test" & return into sLog
   put 0 into sPass
   put 0 into sFail

   testVersion
   testRandomBytes
   testEncoding
   testHashing
   testMemEqual
   testSecretBox
   testAead
   testPwHash
   testKdf
   testSecretStream
   testFileHelpers
   testSign
   testBox
   testSeal
   testKeyExchange
   testPadding

   put return & "----" & return into sLog after sLog
   put "PASSED:" && sPass & "   FAILED:" && sFail after sLog
   return sLog
end sxSelfTest

-- record one assertion
on sxCheck pCondition, pLabel
   if pCondition then
      add 1 to sPass
      put "  ok   " & pLabel & return after sLog
   else
      add 1 to sFail
      put "  FAIL " & pLabel & return after sLog
   end if
end sxCheck

private command sxSection pTitle
   put pTitle & ":" & return after sLog
end sxSection

-- convenience: hex string (decoded from the Data sxBin2Hex returns)
private function sxHexOf pData
   return textDecode(sxBin2Hex(pData), "ascii")
end sxHexOf

private function sxUtf8 pText
   return textEncode(pText, "utf-8")
end sxUtf8

on testVersion
   local tVer
   sxSection "version"
   put sxVersion() into tVer
   sxCheck (tVer is not empty), "sxVersion returns a non-empty string"
   sxCheck ("libsodium" is in tVer), "version names libsodium"
end testVersion

on testRandomBytes
   local tA
   local tB
   sxSection "randombytes"
   put sxRandomBytes(32) into tA
   put sxRandomBytes(32) into tB
   sxCheck (the number of bytes in tA is 32), "sxRandomBytes(32) returns 32 bytes"
   sxCheck (tA is not tB), "two draws differ (entropy is flowing)"
end testRandomBytes

on testEncoding
   local tBin
   local tHex
   local tRound
   sxSection "encoding"
   put sxHex2Bin(textEncode("deadbeef", "ascii")) into tBin
   put sxHexOf(tBin) into tHex
   sxCheck (tHex is "deadbeef"), "hex round trip (deadbeef)"
   put sxBase642Bin(sxBin2Base64(sxUtf8("Hello, xTalk!"))) into tRound
   sxCheck (textDecode(tRound, "utf-8") is "Hello, xTalk!"), "base64 round trip"
end testEncoding

on testHashing
   sxSection "hashing (BLAKE2b)"
   -- published BLAKE2b-256 known-answer vector for "abc"
   sxCheck (sxHexOf(sxHash(sxUtf8("abc"), 32)) is \
      "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"), \
      "BLAKE2b-256(abc) matches the published vector"
   -- a keyed hash differs from the unkeyed hash
   sxCheck (sxHash(sxUtf8("abc"), 32) is not \
      sxHashKeyed(sxUtf8("abc"), sxRandomBytes(32), 32)), \
      "keyed hash differs from unkeyed"
end testHashing

on testMemEqual
   local tX
   sxSection "constant-time compare"
   put sxRandomBytes(32) into tX
   sxCheck (sxMemEqual(tX, tX) is true), "equal buffers compare equal"
   sxCheck (sxMemEqual(tX, sxRandomBytes(32)) is false), "different buffers compare unequal"
end testMemEqual

on testSecretBox
   local tKey
   local tBox
   local tPlain
   local tOk
   sxSection "secretbox"
   put sxRandomBytes(32) into tKey
   put sxSecretBox(sxUtf8("Attack at dawn"), tKey) into tBox
   put sxSecretBoxOpen(tBox, tKey) into tPlain
   sxCheck (textDecode(tPlain, "utf-8") is "Attack at dawn"), "round trip recovers the plaintext"
   -- tamper a byte: open must fail
   put false into tOk
   put numToByte(byteToNum(byte 30 of tBox) bitXor 1) into byte 30 of tBox
   try
      get sxSecretBoxOpen(tBox, tKey)
   catch tErr
      put true into tOk
   end try
   sxCheck tOk, "a tampered ciphertext is rejected"
end testSecretBox

on testAead
   local tKey
   local tAd
   local tBox
   local tOk
   sxSection "aead (XChaCha20-Poly1305)"
   put sxRandomBytes(32) into tKey
   put sxUtf8("v1;application/json") into tAd
   put sxAeadEncrypt(sxUtf8("{ok:true}"), tAd, tKey) into tBox
   sxCheck (textDecode(sxAeadDecrypt(tBox, tAd, tKey), "utf-8") is "{ok:true}"), \
      "round trip with associated data"
   -- wrong associated data must fail
   put false into tOk
   try
      get sxAeadDecrypt(tBox, sxUtf8("v2;application/json"), tKey)
   catch tErr
      put true into tOk
   end try
   sxCheck tOk, "wrong associated data is rejected"
end testAead

on testPwHash
   local tSalt
   local tKey
   local tHash
   sxSection "Argon2id (pwhash)"
   -- deterministic known-answer: pass "password", salt = 16 x 'A', ops 2, mem 1 MiB
   put sxUtf8("AAAAAAAAAAAAAAAA") into tSalt
   put sxPwHash(sxUtf8("password"), tSalt, 32, "2", "1048576") into tKey
   sxCheck (sxHexOf(tKey) is \
      "7216b4357104ed7f8a4e900e9cc7a63a0786855abe0b59340053ee43f841228a"), \
      "Argon2id derivation matches the known-answer vector"
   -- password-string storage + verify
   put sxPwHashStr(sxUtf8("hunter2"), "2", "1048576") into tHash
   sxCheck (sxPwHashStrVerify(textDecode(tHash, "ascii"), sxUtf8("hunter2")) is true), \
      "pwhash_str verify accepts the right passphrase"
   sxCheck (sxPwHashStrVerify(textDecode(tHash, "ascii"), sxUtf8("nope")) is false), \
      "pwhash_str verify rejects the wrong passphrase"
end testPwHash

on testKdf
   local tMaster
   local tCtx
   local tA
   local tB
   sxSection "kdf"
   put sxRandomBytes(32) into tMaster
   put sxUtf8("SXTctx00") into tCtx
   put sxKdfDerive(tMaster, "1", tCtx, 32) into tA
   put sxKdfDerive(tMaster, "2", tCtx, 32) into tB
   sxCheck (the number of bytes in tA is 32), "kdf derives a 32-byte subkey"
   sxCheck (tA is not tB), "different subkey ids give different subkeys"
end testKdf

on testSecretStream
   local tKey
   local tHeader
   local tPushH
   local tPullH
   local tNoAd
   local tC1
   local tC2
   local tTag1
   local tTag2
   local tP1
   local tP2
   sxSection "secretstream"
   put sxRandomBytes(32) into tKey
   put sxUtf8("") into tNoAd
   put sxSecretStreamInitPush(tKey, tHeader) into tPushH
   put sxSecretStreamPush(tPushH, sxUtf8("chunk one "), tNoAd, false) into tC1
   put sxSecretStreamPush(tPushH, sxUtf8("and final"), tNoAd, true) into tC2
   sxFreeStream tPushH
   put sxSecretStreamInitPull(tKey, tHeader) into tPullH
   put sxSecretStreamPull(tPullH, tC1, tNoAd, tTag1) into tP1
   put sxSecretStreamPull(tPullH, tC2, tNoAd, tTag2) into tP2
   sxFreeStream tPullH
   sxCheck (textDecode(tP1, "utf-8") is "chunk one "), "first chunk decrypts"
   sxCheck (textDecode(tP2, "utf-8") is "and final"), "final chunk decrypts"
   sxCheck (sxIsFinalTag(tTag2) is true), "final chunk carries the FINAL tag"
end testSecretStream

on testFileHelpers
   local tKey
   local tSrc
   local tEnc
   local tDec
   local tData
   sxSection "file helpers"
   put sxRandomBytes(32) into tKey
   put specialFolderPath("temporary") & "/sxt_demo_plain.bin" into tSrc
   put specialFolderPath("temporary") & "/sxt_demo.enc" into tEnc
   put specialFolderPath("temporary") & "/sxt_demo_dec.bin" into tDec
   put sxRandomBytes(50000) into tData
   put tData into url ("binfile:" & tSrc)
   sxEncryptFile tSrc, tEnc, tKey
   sxDecryptFile tEnc, tDec, tKey
   sxCheck (url ("binfile:" & tDec) is tData), "file encrypt/decrypt round trip (50 KB)"
   delete file tSrc
   delete file tEnc
   delete file tDec
end testFileHelpers

on testSign
   local tPk
   local tSk
   local tSig
   local tOk
   sxSection "ed25519 sign/verify"
   sxSignKeypair tPk, tSk
   put sxSignDetached(sxUtf8("release v1.0"), tSk) into tSig
   sxCheck (sxSignVerifyDetached(tSig, sxUtf8("release v1.0"), tPk) is true), \
      "a valid signature verifies"
   sxCheck (sxSignVerifyDetached(tSig, sxUtf8("release v1.1"), tPk) is false), \
      "a modified message fails verification"
end testSign

on testBox
   local tApk
   local tAsk
   local tBpk
   local tBsk
   local tBox
   local tOk
   sxSection "public-key box (X25519)"
   sxBoxKeypair tApk, tAsk
   sxBoxKeypair tBpk, tBsk
   put sxBox(sxUtf8("for your eyes only"), tBpk, tAsk) into tBox
   sxCheck (textDecode(sxBoxOpen(tBox, tApk, tBsk), "utf-8") is "for your eyes only"), \
      "A->B box round trip"
   put false into tOk
   try
      get sxBoxOpen(tBox, tApk, tAsk)
   catch tErr
      put true into tOk
   end try
   sxCheck tOk, "a third party cannot open the box"
end testBox

on testSeal
   local tPk
   local tSk
   local tSealed
   sxSection "sealed box (anonymous sender)"
   sxBoxKeypair tPk, tSk
   put sxSeal(sxUtf8("anonymous tip"), tPk) into tSealed
   sxCheck (textDecode(sxSealOpen(tSealed, tPk, tSk), "utf-8") is "anonymous tip"), \
      "seal round trip to the recipient"
end testSeal

on testKeyExchange
   local tCpk
   local tCsk
   local tSpk
   local tSsk
   local tCrx
   local tCtx
   local tSrx
   local tStx
   sxSection "key exchange (kx)"
   sxKeyExchangeKeypair tCpk, tCsk
   sxKeyExchangeKeypair tSpk, tSsk
   sxKeyExchangeClient tCpk, tCsk, tSpk, tCrx, tCtx
   sxKeyExchangeServer tSpk, tSsk, tCpk, tSrx, tStx
   sxCheck (sxMemEqual(tCrx, tStx) is true), "client rx equals server tx"
   sxCheck (sxMemEqual(tCtx, tSrx) is true), "client tx equals server rx"
end testKeyExchange

on testPadding
   local tPadded
   sxSection "padding"
   put sxPad(sxUtf8("hello"), 16) into tPadded
   sxCheck (the number of bytes in tPadded is 16), "pad rounds 5 bytes up to 16"
   sxCheck (textDecode(sxUnpad(tPadded, 16), "utf-8") is "hello"), "unpad recovers the original"
end testPadding
