-- sodium-demo.livecodescript - the SodiumXT showcase stack.
--
-- A professionally laid-out, self-building demo that makes one point clearly:
-- xTalk now has modern, authenticated cryptography that is easy to use. On open
-- it builds a branded, tabbed UI (no design work needed in the IDE), with one
-- panel per capability. Every panel shows the same story: your INPUT, a plain
-- sentence about WHAT the crypto does, the OUTPUT, and a colored STATUS line -
-- green for success, red when authentication correctly REJECTS tampering or a
-- wrong key. That rejection is the headline: unlike the old aes-256-cbc path,
-- these ciphers fail closed.
--
-- Tabs: Secret Key (passphrase encryption), Public Key (X25519 box + sealed
-- box), Signatures (ed25519), Hash & Files (BLAKE2b + C-side file ops), About
-- (the pitch + a one-click self-test).
--
-- To use (requires the SodiumXT extension installed so org.openxtalk.library
-- .sodium is loaded): open as a script-only stack, OR paste this as a stack's
-- script and `send "preOpenStack" to <that stack>`.
--
-- Conventions: bytes cross as Data (textEncode/textDecode at the boundary);
-- functions return a value, commands report; out-params pass a variable. The
-- sx* handlers throw on auth failure, so the demo wraps those in try/catch.
-- Verified statically (tools/check-livecodescript.py); run in OXT to confirm.

local sTab          -- active tab key: enc | key | sign | hash | about
local sEncBlob      -- last sealed base64 blob (Secret Key tab)
local sApk          -- Alice public key (Public Key tab)
local sAsk          -- Alice secret key
local sBpk          -- Bob public key
local sBsk          -- Bob secret key
local sBoxCt        -- last box ciphertext, base64 (canonical, not the display field)
local sSignPk       -- signing public key (Signatures tab)
local sSignSk       -- signing secret key
local sSignSig      -- last signature
local sSignMsg      -- the message that was signed
local sTPass        -- About self-test: passing checks
local sTFail        -- About self-test: failing checks
local sTLog         -- About self-test: running transcript

on preOpenStack
   buildUI
   showTab "enc"
end preOpenStack

-- ==========================================================================
-- Palette. Single RGB source of truth (single-line ifs are checker-safe).
-- ==========================================================================

private function clr pName
   if pName is "headerBg" then return "26,32,53"
   if pName is "headerText" then return "237,240,247"
   if pName is "headerSub" then return "150,160,190"
   if pName is "appBg" then return "239,241,246"
   if pName is "panelBg" then return "255,255,255"
   if pName is "accent" then return "63,94,251"
   if pName is "accentText" then return "255,255,255"
   if pName is "muted" then return "120,128,148"
   if pName is "ink" then return "33,37,48"
   if pName is "ok" then return "26,137,71"
   if pName is "bad" then return "201,52,62"
   if pName is "tabIdle" then return "214,218,228"
   if pName is "mono" then return "244,246,250"
   return "0,0,0"
end clr

-- ==========================================================================
-- Styled control factory. Names carry a "prefix:role" tag: the prefix is the
-- owning tab (or "ui" for chrome), so showTab can toggle a panel by visibility
-- and mouseUp can route by the role.
-- ==========================================================================

private command makeRect pName, pRect, pColorName, pRound
   create graphic pName
   set the rectangle of graphic pName to pRect
   set the style of graphic pName to "rectangle"
   if pRound > 0 then
      set the style of graphic pName to "roundrect"
      set the roundRadius of graphic pName to pRound
   end if
   set the opaque of graphic pName to true
   set the lineSize of graphic pName to 0
   set the backgroundColor of graphic pName to clr(pColorName)
end makeRect

private command makeLabel pName, pRect, pText, pColorName, pSize, pStyle
   create field pName
   set the rectangle of field pName to pRect
   set the lockText of field pName to true
   set the showBorder of field pName to false
   set the opaque of field pName to false
   set the margins of field pName to 4
   set the textFont of field pName to "Helvetica"
   set the textSize of field pName to pSize
   set the textStyle of field pName to pStyle
   set the foregroundColor of field pName to clr(pColorName)
   put pText into field pName
end makeLabel

private command makeInput pName, pRect, pText
   create field pName
   set the rectangle of field pName to pRect
   set the lockText of field pName to false
   set the showBorder of field pName to true
   set the borderWidth of field pName to 1
   set the threeD of field pName to false
   set the opaque of field pName to true
   set the backgroundColor of field pName to clr("panelBg")
   set the textFont of field pName to "Helvetica"
   set the textSize of field pName to 13
   set the foregroundColor of field pName to clr("ink")
   put pText into field pName
end makeInput

private command makeMono pName, pRect
   create field pName
   set the rectangle of field pName to pRect
   set the lockText of field pName to true
   set the showBorder of field pName to true
   set the borderWidth of field pName to 1
   set the threeD of field pName to false
   set the opaque of field pName to true
   set the backgroundColor of field pName to clr("mono")
   set the textFont of field pName to "Courier"
   set the textSize of field pName to 11
   set the foregroundColor of field pName to clr("ink")
   set the vScrollbar of field pName to true
end makeMono

private command makeButton pName, pRect, pLabel, pPrimary
   create button pName
   set the rectangle of button pName to pRect
   set the showName of button pName to true
   set the label of button pName to pLabel
   set the textFont of button pName to "Helvetica"
   set the textSize of button pName to 13
   set the textStyle of button pName to "bold"
   set the threeD of button pName to false
   set the borderWidth of button pName to 0
   set the opaque of button pName to true
   set the autoHilite of button pName to true
   if pPrimary then
      set the backgroundColor of button pName to clr("accent")
      set the foregroundColor of button pName to clr("accentText")
   else
      set the backgroundColor of button pName to clr("tabIdle")
      set the foregroundColor of button pName to clr("ink")
   end if
end makeButton

private command setStatus pName, pText, pState
   put pText into field pName
   if pState is "ok" then
      set the foregroundColor of field pName to clr("ok")
   else if pState is "bad" then
      set the foregroundColor of field pName to clr("bad")
   else
      set the foregroundColor of field pName to clr("muted")
   end if
end setStatus

-- Short hex preview of some bytes, for showing keys/digests without a wall of text.
private function shortHex pData, pMax
   local tHex
   put textDecode(sxBin2Hex(pData), "ascii") into tHex
   if the number of chars in tHex > pMax then
      return char 1 to pMax of tHex & "..."
   end if
   return tHex
end shortHex

-- ==========================================================================
-- UI construction.
-- ==========================================================================

on buildUI
   if there is a field "ui:title" then
      exit buildUI
   end if
   set the width of this stack to 820
   set the height of this stack to 648
   set the name of this stack to "SodiumXT Demo"
   set the backgroundColor of this stack to clr("appBg")

   -- Header bar.
   makeRect "ui:header", "0,0,820,64", "headerBg", 0
   makeLabel "ui:title", "24,9,520,40", "SodiumXT", "headerText", 23, "bold"
   makeLabel "ui:subtitle", "26,40,560,60", "modern cryptography for xTalk, made easy", "headerSub", 12, "plain"
   makeLabel "ui:ver", "560,16,800,40", "", "headerSub", 12, "plain"
   set the textAlign of field "ui:ver" to "right"
   try
      put sxVersion() into field "ui:ver"
   catch tErr
      put "library not loaded" into field "ui:ver"
   end try

   -- Tab bar.
   makeButton "ui:tabEncrypt", "24,76,173,104", "Secret Key", false
   makeButton "ui:tabKeys", "179,76,328,104", "Public Key", false
   makeButton "ui:tabSign", "334,76,483,104", "Signatures", false
   makeButton "ui:tabHash", "489,76,638,104", "Hash & Files", false
   makeButton "ui:tabAbout", "644,76,793,104", "About", false

   -- Content panel + footer.
   makeRect "ui:panel", "24,112,796,604", "panelBg", 10
   makeLabel "ui:footer", "24,612,796,638", "Backed by libsodium through the SodiumXT C shim. Every cipher here is authenticated: tampering and wrong keys are rejected.", "muted", 11, "plain"

   buildEncTab
   buildKeyTab
   buildSignTab
   buildHashTab
   buildAboutTab
end buildUI

on buildEncTab
   makeLabel "enc:h", "48,126,748,154", "Passphrase-based authenticated encryption", "ink", 16, "bold"
   makeLabel "enc:exp", "48,158,748,224", "Step 1: type a passphrase and a message. Step 2: Encrypt seals it (a random salt + Argon2id derive the key; secretbox adds a Poly1305 tag). Step 3: Decrypt to recover it, or Flip a byte then Decrypt to watch the tag reject the tampered ciphertext.", "muted", 12, "plain"
   makeLabel "enc:lp", "48,234,300,256", "Passphrase", "ink", 12, "bold"
   makeInput "enc:pass", "48,258,430,286", "correct horse battery staple"
   makeLabel "enc:lm", "48,294,300,316", "Message", "ink", 12, "bold"
   makeInput "enc:msg", "48,318,748,372", "Meet at the docks at midnight."
   makeButton "enc:encrypt", "48,386,210,418", "1. Encrypt", true
   makeButton "enc:decrypt", "220,386,360,418", "2. Decrypt", false
   makeButton "enc:tamper", "560,386,748,418", "Flip a byte", false
   makeLabel "enc:lo", "48,426,748,446", "Sealed output (base64 of salt + nonce + ciphertext + MAC)", "muted", 11, "plain"
   makeMono "enc:out", "48,448,748,540"
   makeLabel "enc:status", "48,556,748,596", "Type a passphrase and a message, then click 1. Encrypt.", "muted", 12, "plain"
end buildEncTab

on buildKeyTab
   makeLabel "key:h", "48,126,748,154", "Public-key encryption (X25519)", "ink", 16, "bold"
   makeLabel "key:exp", "48,158,748,224", "Alice and Bob each hold a keypair. Alice encrypts to Bob's PUBLIC key; only Bob's SECRET key can open it, and a sealed box even hides who sent it. Work left to right: 1. Generate the keypairs, 2. Encrypt to Bob, 3. Bob opens. Then try the Eavesdropper.", "muted", 12, "plain"
   makeButton "key:gen", "48,234,330,266", "1. Generate keypairs", true
   makeMono "key:keys", "342,234,748,320"
   makeLabel "key:lm", "48,328,400,348", "Message from Alice to Bob", "ink", 12, "bold"
   makeInput "key:msg", "48,350,748,388", "For your eyes only, Bob."
   makeButton "key:box", "48,400,230,432", "2. Encrypt to Bob", true
   makeButton "key:open", "240,400,380,432", "3. Bob opens", false
   makeButton "key:eve", "560,400,748,432", "Eavesdropper tries", false
   makeMono "key:out", "48,442,748,540"
   makeLabel "key:status", "48,556,748,596", "Click 1. Generate keypairs to begin.", "muted", 12, "plain"
end buildKeyTab

on buildSignTab
   makeLabel "sign:h", "48,126,748,154", "Digital signatures (ed25519)", "ink", 16, "bold"
   makeLabel "sign:exp", "48,158,748,224", "Sign a statement with a SECRET key; anyone with the matching PUBLIC key can verify it. Steps: 1. Generate a keypair, 2. Sign the statement, 3. Verify. Then edit one character of the statement and Verify again - the signature no longer matches.", "muted", 12, "plain"
   makeButton "sign:gen", "48,234,330,266", "1. Generate keypair", true
   makeMono "sign:keys", "342,234,748,300"
   makeLabel "sign:lm", "48,308,400,328", "Statement to sign", "ink", 12, "bold"
   makeInput "sign:msg", "48,330,748,370", "I, Alice, authorize the release of version 1.0."
   makeButton "sign:sign", "48,382,210,414", "2. Sign", true
   makeButton "sign:verify", "220,382,360,414", "3. Verify", false
   makeLabel "sign:lo", "48,422,748,442", "Signature (64 bytes, hex)", "muted", 11, "plain"
   makeMono "sign:out", "48,444,748,540"
   makeLabel "sign:status", "48,556,748,596", "Click 1. Generate keypair, then Sign. Edit the statement and Verify to see it fail.", "muted", 12, "plain"
end buildSignTab

on buildHashTab
   makeLabel "hash:h", "48,126,748,154", "Hashing and whole-file encryption", "ink", 16, "bold"
   makeLabel "hash:exp", "48,158,748,224", "BLAKE2b is a fast cryptographic fingerprint. Type text and Hash it - then change one character and hash again to see a completely different digest. Or pick a file to hash or encrypt: files are processed chunk-by-chunk in C, so size is no object.", "muted", 12, "plain"
   makeLabel "hash:lm", "48,234,400,256", "Text to hash", "ink", 12, "bold"
   makeInput "hash:msg", "48,258,748,298", "The quick brown fox jumps over the lazy dog"
   makeButton "hash:hash", "48,310,280,342", "Hash text (BLAKE2b-256)", true
   makeMono "hash:out", "48,352,748,468"
   makeButton "hash:hashfile", "48,480,260,512", "Hash a file...", false
   makeButton "hash:encfile", "272,480,484,512", "Encrypt a file...", false
   makeLabel "hash:status", "48,556,748,596", "Hash the text above, or pick a file to hash or encrypt.", "muted", 12, "plain"
end buildHashTab

on buildAboutTab
   makeLabel "about:h", "48,126,748,154", "SodiumXT", "ink", 16, "bold"
   makeLabel "about:exp", "48,158,748,300", "SodiumXT brings modern, audited cryptography to OpenXTalk and the xTalk family through one library: authenticated encryption (secretbox and AEAD), Argon2id password hashing, a streaming cipher for large files, X25519 public-key boxes and sealed boxes, ed25519 signatures, BLAKE2b hashing, key derivation and key exchange, and a real CSPRNG. It wraps libsodium behind a flat C ABI with a thin LiveCode Builder layer, so any xTalk app can drop its hand-rolled crypto and just call sx*. Every cipher here authenticates: tampering and wrong keys fail closed.", "muted", 12, "plain"
   makeLabel "about:hint", "48,306,748,348", "New here? Open the Secret Key tab, type a passphrase, click Encrypt, then click Flip a byte and Decrypt - watch the tampering get rejected. That rejection is the whole point.", "accent", 12, "bold"
   makeButton "about:selftest", "48,356,300,388", "Run the full self-test", true
   makeMono "about:out", "48,398,748,540"
   makeLabel "about:status", "48,556,748,596", "Click Run the full self-test to check every primitive against the live library.", "muted", 12, "plain"
end buildAboutTab

-- ==========================================================================
-- Tab switching.
-- ==========================================================================

on showTab pKey
   local tI
   local tN
   local tPre
   put pKey into sTab
   set the itemDelimiter to ":"
   repeat with tI = 1 to the number of controls of this card
      put the short name of control tI into tN
      put item 1 of tN into tPre
      if tPre is "enc" or tPre is "key" or tPre is "sign" or tPre is "hash" or tPre is "about" then
         set the visible of control tI to (tPre is pKey)
      end if
   end repeat
   restyleTabs
end showTab

on restyleTabs
   styleTab "ui:tabEncrypt", (sTab is "enc")
   styleTab "ui:tabKeys", (sTab is "key")
   styleTab "ui:tabSign", (sTab is "sign")
   styleTab "ui:tabHash", (sTab is "hash")
   styleTab "ui:tabAbout", (sTab is "about")
end restyleTabs

on styleTab pName, pActive
   if pActive then
      set the backgroundColor of button pName to clr("accent")
      set the foregroundColor of button pName to clr("accentText")
   else
      set the backgroundColor of button pName to clr("tabIdle")
      set the foregroundColor of button pName to clr("ink")
   end if
end styleTab

-- ==========================================================================
-- Click routing: a control's short name is "prefix:role"; dispatch by prefix.
-- ==========================================================================

on mouseUp
   local tName
   local tPrefix
   local tRole
   put the short name of the target into tName
   set the itemDelimiter to ":"
   put item 1 of tName into tPrefix
   put item 2 of tName into tRole
   if tPrefix is "ui" then
      handleChrome tRole
   else if tPrefix is "enc" then
      handleEnc tRole
   else if tPrefix is "key" then
      handleKey tRole
   else if tPrefix is "sign" then
      handleSign tRole
   else if tPrefix is "hash" then
      handleHash tRole
   else if tPrefix is "about" then
      handleAbout tRole
   end if
end mouseUp

on handleChrome pRole
   if pRole is "tabEncrypt" then
      showTab "enc"
   else if pRole is "tabKeys" then
      showTab "key"
   else if pRole is "tabSign" then
      showTab "sign"
   else if pRole is "tabHash" then
      showTab "hash"
   else if pRole is "tabAbout" then
      showTab "about"
   end if
end handleChrome

-- ==========================================================================
-- Secret Key tab: passphrase -> Argon2id -> secretbox, with a tamper demo.
-- ==========================================================================

on handleEnc pRole
   if pRole is "encrypt" then
      doEncrypt
   else if pRole is "decrypt" then
      doDecrypt
   else if pRole is "tamper" then
      doTamper
   end if
end handleEnc

on doEncrypt
   local tSalt
   local tKey
   local tBox
   if field "enc:pass" is empty then
      setStatus "enc:status", "Enter a passphrase first.", "bad"
      exit doEncrypt
   end if
   put sxRandomBytes(16) into tSalt
   put sxPwHash(textEncode(field "enc:pass", "utf-8"), tSalt, 32, "2", sxPwMemInteractive()) into tKey
   put sxSecretBox(textEncode(field "enc:msg", "utf-8"), tKey) into tBox
   put textDecode(sxBin2Base64(tSalt & tBox), "ascii") into sEncBlob
   put sEncBlob into field "enc:out"
   setStatus "enc:status", "Sealed" && (the number of bytes in textEncode(field "enc:msg", "utf-8")) & "-byte message into" && (the number of bytes in (tSalt & tBox)) & " bytes. Now try Decrypt, or Flip a byte.", "ok"
end doEncrypt

on doDecrypt
   local tRaw
   local tSalt
   local tBox
   local tKey
   if sEncBlob is empty then
      setStatus "enc:status", "Nothing to decrypt yet - click Encrypt first.", "bad"
      exit doDecrypt
   end if
   put sxBase642Bin(textEncode(sEncBlob, "ascii")) into tRaw
   if the number of bytes in tRaw < 17 then
      setStatus "enc:status", "That is not a valid sealed blob.", "bad"
      exit doDecrypt
   end if
   put byte 1 to 16 of tRaw into tSalt
   put byte 17 to -1 of tRaw into tBox
   put sxPwHash(textEncode(field "enc:pass", "utf-8"), tSalt, 32, "2", sxPwMemInteractive()) into tKey
   try
      put "Recovered: " & textDecode(sxSecretBoxOpen(tBox, tKey), "utf-8") into field "enc:out"
      setStatus "enc:status", "Decrypted and authenticated. The Poly1305 tag verified.", "ok"
   catch tErr
      setStatus "enc:status", "REJECTED: wrong passphrase, or the ciphertext was tampered with.", "bad"
   end try
end doDecrypt

-- Flip one byte of the sealed blob in place, to show open() rejects it.
on doTamper
   local tRaw
   local tLen
   local tPos
   if sEncBlob is empty then
      setStatus "enc:status", "Encrypt something first, then flip a byte.", "bad"
      exit doTamper
   end if
   put sxBase642Bin(textEncode(sEncBlob, "ascii")) into tRaw
   put the number of bytes in tRaw into tLen
   put 17 + (tLen - 17) div 2 into tPos
   put numToByte(byteToNum(byte tPos of tRaw) bitXor 1) into byte tPos of tRaw
   put textDecode(sxBin2Base64(tRaw), "ascii") into field "enc:out"
   put field "enc:out" into sEncBlob
   setStatus "enc:status", "Flipped one ciphertext byte. Now click Decrypt - it must be rejected.", "muted"
end doTamper

-- ==========================================================================
-- Public Key tab: X25519 box + sealed box between Alice and Bob.
-- ==========================================================================

on handleKey pRole
   if pRole is "gen" then
      doKeygen
   else if pRole is "box" then
      doBox
   else if pRole is "open" then
      doBoxOpen
   else if pRole is "eve" then
      doBoxEve
   end if
end handleKey

on doKeygen
   sxBoxKeypair sApk, sAsk
   sxBoxKeypair sBpk, sBsk
   put "Alice public: " & shortHex(sApk, 32) & return & "Bob public:   " & shortHex(sBpk, 32) & return & "(secret keys held privately by each party)" into field "key:keys"
   put empty into field "key:out"
   setStatus "key:status", "Two X25519 keypairs generated. Encrypt a message from Alice to Bob.", "ok"
end doKeygen

on doBox
   local tBox
   if sApk is empty then
      setStatus "key:status", "Generate keypairs first.", "bad"
      exit doBox
   end if
   put sxBox(textEncode(field "key:msg", "utf-8"), sBpk, sAsk) into tBox
   put textDecode(sxBin2Base64(tBox), "ascii") into sBoxCt
   put sBoxCt into field "key:out"
   setStatus "key:status", "Encrypted to Bob's public key with Alice's secret key. Click Bob opens.", "ok"
end doBox

on doBoxOpen
   local tBox
   if sBoxCt is empty then
      setStatus "key:status", "Encrypt a message first.", "bad"
      exit doBoxOpen
   end if
   put sxBase642Bin(textEncode(sBoxCt, "ascii")) into tBox
   try
      put "Bob reads: " & textDecode(sxBoxOpen(tBox, sApk, sBsk), "utf-8") into field "key:out"
      setStatus "key:status", "Bob opened it with his secret key and Alice's public key.", "ok"
   catch tErr
      setStatus "key:status", "REJECTED.", "bad"
   end try
end doBoxOpen

-- An eavesdropper holding the wrong secret key cannot open the box.
on doBoxEve
   local tBox
   local tEpk
   local tEsk
   if sBoxCt is empty then
      setStatus "key:status", "Encrypt a message first.", "bad"
      exit doBoxEve
   end if
   put sxBase642Bin(textEncode(sBoxCt, "ascii")) into tBox
   sxBoxKeypair tEpk, tEsk
   try
      get sxBoxOpen(tBox, sApk, tEsk)
      setStatus "key:status", "Unexpected: the eavesdropper opened it (should not happen).", "bad"
   catch tErr
      setStatus "key:status", "REJECTED: a third party with the wrong key cannot open Bob's box.", "ok"
   end try
end doBoxEve

-- ==========================================================================
-- Signatures tab: ed25519 sign / verify, including the tamper case.
-- ==========================================================================

on handleSign pRole
   if pRole is "gen" then
      doSignGen
   else if pRole is "sign" then
      doSign
   else if pRole is "verify" then
      doVerify
   end if
end handleSign

on doSignGen
   sxSignKeypair sSignPk, sSignSk
   put "public key: " & shortHex(sSignPk, 48) into field "sign:keys"
   put empty into field "sign:out"
   put empty into sSignSig
   setStatus "sign:status", "Signing keypair generated. Type a statement and Sign it.", "ok"
end doSignGen

on doSign
   if sSignSk is empty then
      setStatus "sign:status", "Generate a signing keypair first.", "bad"
      exit doSign
   end if
   put field "sign:msg" into sSignMsg
   put sxSignDetached(textEncode(sSignMsg, "utf-8"), sSignSk) into sSignSig
   put textDecode(sxBin2Hex(sSignSig), "ascii") into field "sign:out"
   setStatus "sign:status", "Signed. Now Verify - or edit the statement first and watch it fail.", "ok"
end doSign

on doVerify
   if sSignSig is empty then
      setStatus "sign:status", "Sign a statement first.", "bad"
      exit doVerify
   end if
   if sxSignVerifyDetached(sSignSig, textEncode(field "sign:msg", "utf-8"), sSignPk) then
      setStatus "sign:status", "VALID: the signature matches this exact statement.", "ok"
   else
      setStatus "sign:status", "INVALID: the statement was changed since it was signed.", "bad"
   end if
end doVerify

-- ==========================================================================
-- Hash & Files tab.
-- ==========================================================================

on handleHash pRole
   if pRole is "hash" then
      doHashText
   else if pRole is "hashfile" then
      doHashFile
   else if pRole is "encfile" then
      doEncFile
   end if
end handleHash

on doHashText
   put "BLAKE2b-256:" && return & textDecode(sxBin2Hex(sxHash(textEncode(field "hash:msg", "utf-8"), 32)), "ascii") into field "hash:out"
   setStatus "hash:status", "Hashed. Change one character of the text and hash again to see a totally different digest.", "ok"
end doHashText

on doHashFile
   local tPath
   answer file "Choose a file to hash:"
   put it into tPath
   if tPath is empty then
      exit doHashFile
   end if
   try
      put "File: " & tPath & return & "BLAKE2b-256:" && return & textDecode(sxBin2Hex(sxHashFile(tPath, 32)), "ascii") into field "hash:out"
      setStatus "hash:status", "Hashed the file chunk-by-chunk C-side - the bytes never entered a variable.", "ok"
   catch tErr
      setStatus "hash:status", "Could not hash that file:" && tErr, "bad"
   end try
end doHashFile

on doEncFile
   local tPath
   local tKey
   answer file "Choose a file to encrypt (a .enc copy is written beside it):"
   put it into tPath
   if tPath is empty then
      exit doEncFile
   end if
   put sxRandomBytes(32) into tKey
   try
      sxEncryptFile tPath, (tPath & ".enc"), tKey
      put "Encrypted:" && return & tPath & return & "  ->  " & tPath & ".enc" & return & return & "Key (hex, keep it safe - this demo does not store it):" & return & textDecode(sxBin2Hex(tKey), "ascii") into field "hash:out"
      setStatus "hash:status", "Encrypted with a random key, streamed C-side. The .enc file is authenticated (truncation is detectable).", "ok"
   catch tErr
      setStatus "hash:status", "Could not encrypt that file:" && tErr, "bad"
   end try
end doEncFile

-- ==========================================================================
-- About tab: a compact self-test against the live library.
-- ==========================================================================

on handleAbout pRole
   if pRole is "selftest" then
      doSelfTest
   end if
end handleAbout

on doSelfTest
   local tKey
   local tBox
   local tPk
   local tSk
   local tSig
   put 0 into sTPass
   put 0 into sTFail
   put "Running checks against" && sxVersion() & return & return into sTLog

   -- secretbox round trip, then a wrong key must be rejected
   put sxRandomBytes(32) into tKey
   put sxSecretBox(textEncode("hello", "utf-8"), tKey) into tBox
   checkInto (textDecode(sxSecretBoxOpen(tBox, tKey), "utf-8") is "hello"), "secretbox round trip"
   checkInto (not openSucceeds(tBox, sxRandomBytes(32))), "secretbox rejects a wrong key"

   -- Argon2id and BLAKE2b pinned to published known-answer vectors
   checkInto (textDecode(sxBin2Hex(sxPwHash(textEncode("password", "utf-8"), textEncode("AAAAAAAAAAAAAAAA", "utf-8"), 32, "2", "1048576")), "ascii") is "7216b4357104ed7f8a4e900e9cc7a63a0786855abe0b59340053ee43f841228a"), "Argon2id known-answer vector"
   checkInto (textDecode(sxBin2Hex(sxHash(textEncode("abc", "utf-8"), 32)), "ascii") is "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"), "BLAKE2b-256(abc) vector"

   -- ed25519 sign / verify, and the tamper case
   sxSignKeypair tPk, tSk
   put sxSignDetached(textEncode("release", "utf-8"), tSk) into tSig
   checkInto (sxSignVerifyDetached(tSig, textEncode("release", "utf-8"), tPk)), "ed25519 signature verifies"
   checkInto (not sxSignVerifyDetached(tSig, textEncode("RELEASE", "utf-8"), tPk)), "altered message fails verification"

   -- the CSPRNG produces a value in range
   checkInto (sxRandomUniform(2) >= 0), "uniform random produces a value"

   put return & (sTPass + sTFail) & " checks run." after sTLog
   put sTLog into field "about:out"
   if sTFail is 0 then
      setStatus "about:status", "ALL " & sTPass & " CHECKS PASSED against the live libsodium.", "ok"
   else
      setStatus "about:status", sTFail && "check(s) FAILED - see the log.", "bad"
   end if
end doSelfTest

-- Record one check into the running self-test transcript (script-local state).
private command checkInto pCond, pLabel
   if pCond then
      add 1 to sTPass
      put "  ok    " & pLabel & return after sTLog
   else
      add 1 to sTFail
      put "  FAIL  " & pLabel & return after sTLog
   end if
end checkInto

-- True if opening the box with this key succeeds (no throw).
private function openSucceeds pBox, pKey
   try
      get sxSecretBoxOpen(pBox, pKey)
      return true
   catch tErr
      return false
   end try
end openSucceeds
