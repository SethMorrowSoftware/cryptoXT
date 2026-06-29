-- sodium-demo.livecodescript - a small interactive SodiumXT demo stack.
--
-- This is the script of a demo stack. On open it builds its own UI (a passphrase
-- field, a message field, an output field, and Encrypt / Decrypt / Hash
-- buttons), and routes button clicks by name. It shows the headline use case:
-- passphrase-based AUTHENTICATED encryption (the upgrade SodiumXT brings over
-- the old aes-256-cbc + weak-KDF path) - a random salt is generated, the key is
-- derived with Argon2id, the message is sealed with secretbox, and the salt is
-- stored alongside the ciphertext so decryption can re-derive the key.
--
-- To use (requires the SodiumXT extension installed so org.openxtalk.library
-- .sodium is loaded): open this as a script-only stack, OR create a stack, paste
-- this as its stack script, and `send "preOpenStack" to <that stack>`. Then type
-- a passphrase and a message and click Encrypt / Decrypt / Hash.
--
-- Verified statically (tools/check-livecodescript.py); run it in OXT to confirm.

on preOpenStack
   buildDemoUI
end preOpenStack

-- Build the controls once (idempotent).
on buildDemoUI
   if there is a field "fIn" then
      exit buildDemoUI
   end if
   set the width of this stack to 540
   set the height of this stack to 440
   set the name of this stack to "SodiumXT Demo"

   makeLabel "lPass", "Passphrase", "20,16,520,40"
   makeField "fPass", "20,42,520,72"
   makeLabel "lIn", "Message", "20,84,520,108"
   makeField "fIn", "20,110,520,210"
   makeLabel "lOut", "Output (salt + ciphertext, base64)", "20,222,520,246"
   makeField "fOut", "20,248,520,348"

   makeButton "Encrypt", "20,364,170,400"
   makeButton "Decrypt", "185,364,355,400"
   makeButton "Hash", "370,364,520,400"

   put "secret passphrase" into field "fPass"
   put "Attack at dawn." into field "fIn"
end buildDemoUI

private command makeField pName, pRect
   create field pName
   set the rectangle of field pName to pRect
   set the lockText of field pName to false
end makeField

private command makeLabel pName, pText, pRect
   create field pName
   set the rectangle of field pName to pRect
   set the lockText of field pName to true
   set the showBorder of field pName to false
   set the backgroundColor of field pName to empty
   put pText into field pName
end makeLabel

private command makeButton pName, pRect
   create button pName
   set the rectangle of button pName to pRect
end makeButton

-- Route button clicks (the buttons carry no script of their own).
on mouseUp
   local tName
   put the short name of the target into tName
   if tName is "Encrypt" then
      doEncrypt
   else if tName is "Decrypt" then
      doDecrypt
   else if tName is "Hash" then
      doHash
   end if
end mouseUp

-- Passphrase -> Argon2id key -> secretbox. Output is base64(salt + box), so the
-- random salt travels with the ciphertext and Decrypt can re-derive the key.
on doEncrypt
   local tSalt
   local tKey
   local tBox
   put sxRandomBytes(16) into tSalt
   put sxPwHash(textEncode(field "fPass", "utf-8"), tSalt, 32, "2", "67108864") into tKey
   put sxSecretBox(textEncode(field "fIn", "utf-8"), tKey) into tBox
   put textDecode(sxBin2Base64(tSalt & tBox), "ascii") into field "fOut"
end doEncrypt

on doDecrypt
   local tBlob
   local tSalt
   local tBox
   local tKey
   put sxBase642Bin(textEncode(field "fOut", "ascii")) into tBlob
   if the number of bytes in tBlob < 17 then
      answer "Nothing to decrypt yet - click Encrypt first."
      exit doDecrypt
   end if
   put byte 1 to 16 of tBlob into tSalt
   put byte 17 to -1 of tBlob into tBox
   put sxPwHash(textEncode(field "fPass", "utf-8"), tSalt, 32, "2", "67108864") into tKey
   try
      put textDecode(sxSecretBoxOpen(tBox, tKey), "utf-8") into field "fIn"
   catch tErr
      answer "Wrong passphrase, or the ciphertext was tampered with."
   end try
end doDecrypt

on doHash
   put textDecode(sxBin2Hex(sxHash(textEncode(field "fIn", "utf-8"), 32)), "ascii") \
      into field "fOut"
end doHash
