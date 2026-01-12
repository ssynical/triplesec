local TripleSec = require(game:GetService("ServerStorage").INIT)

local function string_to_bytes(str: string): { number }
	local bytes = table.create(#str)
	for i = 1, #str do bytes[i] = string.byte(str, i) end
	return bytes
end

local function bytes_to_string(bytes: { number }): string
	local chars = table.create(#bytes)
	for i = 1, #bytes do chars[i] = string.char(bytes[i]) end
	return table.concat(chars)
end

local password = "SecurePassword123!"
local message = "This is a secret message that needs encryption."
local plaintext = string_to_bytes(message)

print("Original message:", message)
print("Message length:", #plaintext, "bytes")

local iterations = 1000
local cipher = "AES-Twofish-Serpent"
local hash = "SHA512"

print("\nEncrypting with:")
print("  Cipher cascade:", cipher)
print("  Hash algorithm:", hash)
print("  PBKDF2 iterations:", iterations)

local startTime = os.clock()
local result = TripleSec.simple_encrypt(password, plaintext, cipher, hash, iterations)
local encryptTime = os.clock() - startTime

print("\nEncryption complete in", string.format("%.3f", encryptTime), "seconds")
print("Salt length:", #result.salt, "bytes")
print("Ciphertext length:", #result.ciphertext, "bytes")

startTime = os.clock()
local decrypted = TripleSec.simple_decrypt(password, result.salt, result.ciphertext, cipher, hash, iterations)
local decryptTime = os.clock() - startTime

if decrypted then
	local decryptedMessage = bytes_to_string(decrypted)
	print("\nDecryption complete in", string.format("%.3f", decryptTime), "seconds")
	print("Decrypted message:", decryptedMessage)
	print("Match:", decryptedMessage == message and "SUCCESS" or "FAILED")
else
	print("\nDecryption failed - invalid padding or wrong password")
end

local ciphers: { TripleSec.CascadeType } = { "AES", "Serpent", "Twofish", "AES-Twofish", "Twofish-Serpent" }

for _, c in ipairs(ciphers) do
	local res = TripleSec.simple_encrypt(password, plaintext, c, "SHA512", 100)
	local dec = TripleSec.simple_decrypt(password, res.salt, res.ciphertext, c, "SHA512", 100)
	local status = dec and bytes_to_string(dec) == message and "OK" or "FAIL"
	print(c .. ":", status)
end
