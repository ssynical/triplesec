local TripleSec = require(game:GetService("ServerStorage").INIT)
local password = "MyPassword123"
local message = "Hello, World!"

local plaintext = {}
for i = 1, #message do
	plaintext[i] = string.byte(message, i)
end

local blockSize = 16
local paddingLength = blockSize - (#plaintext % blockSize)
if paddingLength == 0 then paddingLength = blockSize end

for i = 1, paddingLength do
	table.insert(plaintext, paddingLength)
end

print("Original length:", #message)
print("Padded length:", #plaintext)

local iterations = 100
local result = TripleSec.simple_encrypt(password, plaintext, "AES-Twofish-Serpent", "SHA512", iterations)
print("Salt:", table.concat(result.salt, ", "))
print("Encrypted:", table.concat(result.ciphertext, ", "))

local decrypted = TripleSec.simple_decrypt(password, result.salt, result.ciphertext, "AES-Twofish-Serpent", "SHA512", iterations)

local originalLength = #decrypted - decrypted[#decrypted]
local decryptedStr = ""
for i = 1, originalLength do
	decryptedStr = decryptedStr .. string.char(decrypted[i])
end

print("Decrypted:", decryptedStr)